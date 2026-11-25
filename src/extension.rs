//! Optional site extension tables.
//!
//! A node binary may give the registry an [`Extension`] (for example to keep an earlier product
//! name working on its own nodes). The open binary installs none; every lookup then falls back
//! to the plain behavior. The tables:
//!
//! | Table | Read by |
//! |---|---|
//! | `env_aliases`, `env_notes` | `SCAPEGOAT_API` and `SCAPEGOAT_CONFIG`: the variable, then its aliases (with a note) |
//! | `config_fallbacks`, `config_fallback_note` | the config path when `/etc/scapegoat/scapegoat.toml` is absent |
//! | `profile_dirs` | profile lookup, after the site profiles directory |
//! | `header_aliases` | the API's `X-Scapegoat-Source` and `X-Scapegoat-User` |
//! | `extra_island_urls` | island status: more URLs beside `scapegoat/<node>/<session>/status` |

use crate::config::Config;

/// More island status URLs for one session: `(base, config, session id)`, `base` without a
/// trailing slash.
pub type IslandUrls = fn(&str, &Config, &str) -> Vec<String>;

#[derive(Clone, Default)]
pub struct Extension {
    /// Variable -> other names read when it is unset or empty, in order.
    pub env_aliases: Vec<(String, Vec<String>)>,
    /// Alias -> the note returned when the value came from it.
    pub env_notes: Vec<(String, String)>,
    /// Config paths tried, in order, when the default config does not exist.
    pub config_fallbacks: Vec<String>,
    /// The note for a fallback config; `{path}` and `{default}` are replaced.
    pub config_fallback_note: String,
    /// Profile directories searched after the site profiles directory.
    pub profile_dirs: Vec<String>,
    /// Header -> other header names read when it is absent or empty, in order.
    pub header_aliases: Vec<(String, Vec<String>)>,
    pub extra_island_urls: Option<IslandUrls>,
}

fn table<'a, T>(t: &'a [(String, T)], key: &str) -> Option<&'a T> {
    t.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

impl Extension {
    /// `$name`, then any alias. -> (value, note).
    pub fn env(&self, name: &str, getenv: impl Fn(&str) -> Option<String>) -> (Option<String>, String) {
        let set = |n: &str| getenv(n).filter(|v| !v.is_empty());
        if let Some(v) = set(name) {
            return (Some(v), String::new());
        }
        for alias in table(&self.env_aliases, name).into_iter().flatten() {
            if let Some(v) = set(alias) {
                return (Some(v), table(&self.env_notes, alias).cloned().unwrap_or_default());
            }
        }
        (None, String::new())
    }

    pub fn fallback_note(&self, path: &str, default: &str) -> String {
        self.config_fallback_note.replace("{path}", path).replace("{default}", default)
    }

    /// The header, then any alias; "" when none is set.
    pub fn header<'a>(&self, lookup: impl Fn(&str) -> Option<&'a str>, name: &str) -> String {
        if let Some(v) = lookup(name).filter(|v| !v.is_empty()) {
            return v.to_string();
        }
        for alias in table(&self.header_aliases, name).into_iter().flatten() {
            if let Some(v) = lookup(alias).filter(|v| !v.is_empty()) {
                return v.to_string();
            }
        }
        String::new()
    }

    pub fn island_urls(&self, base: &str, cfg: &Config, sid: &str) -> Vec<String> {
        self.extra_island_urls.map(|f| f(base, cfg, sid)).unwrap_or_default()
    }
}

/// The installed registry's extension (empty when none was given).
pub fn current() -> Extension {
    crate::protocol::Registry::current().extension().clone()
}

fn real_env(n: &str) -> Option<String> {
    std::env::var(n).ok()
}

/// `$name`, then any alias the installed extension declares. -> (value, note).
pub fn env(name: &str) -> (Option<String>, String) {
    current().env(name, real_env)
}
