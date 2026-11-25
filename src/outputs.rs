// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! C2 outputs. The encoder comes with the outputs module of the port; until then every
//! configured output is reported off, with the reason.

use crate::protocol::Track;
use serde_json::{json, Map, Value};

pub struct OutputLayer {
    pub specs: Map<String, Value>,
    pub error: String,
}

impl OutputLayer {
    pub fn new(specs: &Map<String, Value>, _island_rest: &str, _transformers_path: &str) -> OutputLayer {
        let active = specs.values().any(|s| s["enabled"] == true);
        let error = if active { "C2 outputs are not in this build of scapegoat yet".to_string() } else { String::new() };
        OutputLayer { specs: specs.clone(), error }
    }

    pub fn start(&self) {}

    pub fn stop(&self) {}

    /// (output name, enabled, wants this session) for the one-track-path warning.
    pub fn wants(&self) -> Vec<(String, bool, Vec<String>)> {
        self.specs
            .iter()
            .map(|(n, s)| {
                (
                    n.clone(),
                    s["enabled"] == true,
                    s["sessions"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
                )
            })
            .collect()
    }

    pub fn publish(&self, _session_id: &str, _tracks: Vec<Track>) -> Result<(), String> {
        Ok(())
    }

    pub fn status(&self) -> Value {
        let outs: Vec<Value> = self
            .specs
            .iter()
            .map(|(n, s)| {
                json!({"name": n, "format": s["format"], "enabled": s["enabled"], "to": s["to"],
                       "sessions": if s["sessions"].as_array().is_none_or(|a| a.is_empty()) { json!("all") } else { s["sessions"].clone() },
                       "sent": 0, "errors": 0, "dropped": 0, "last_error": "", "last_sent_age_s": null, "context": s["context"]})
            })
            .collect();
        json!({"error": self.error, "transformers": null, "tracks_in": 0, "encode_errors": 0, "last_encode_error": "", "outputs": outs})
    }
}
