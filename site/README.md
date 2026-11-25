# site

The landing page published to GitHub Pages by `.github/workflows/pages.yml`.
One static page: no framework, no external requests, no web fonts, light and dark.

## Files

| File | What it is |
|---|---|
| `index.html` | the page |
| `assets/site.css` | its styles, light and dark (`prefers-color-scheme`) |
| `assets/site.js` | the copy buttons and the first screen's replay |
| `assets/icon.svg` | the page icon |
| `assets/from-tree/` | git-ignored; written by `build.py` from the tree |
| `session.json` | the session the first screen replays, written by `record.py` |
| `record.py` | records `session.json`: `scapegoat serve` and `scapegoat sim toy` on 127.0.0.1, the simulator stopped once and started again (about 40 s) |
| `build.py` | copies `assets/from-tree/`, checks every number and placeholder, runs `fitcheck.py` |
| `fitcheck.py` | loads the page in headless Chrome at 1440 and 390 px; fails when a command box is cut off or the page scrolls sideways |

## Preview

```sh
python3 -I site/build.py
python3 -m http.server 8000 --directory site    # then open http://127.0.0.1:8000/
```

## Where each number comes from

Every number is in an element with `data-measure="<key>"`; `build.py` measures the key
from the tree and fails if the page says something else.

| Key | On the page | Measured as |
|---|---|---|
| (none) | | The page states no numbers: none of the project's counts is something its reader would ask about. |

## The first screen

The replay plays `session.json` line by line at its recorded times, three times faster,
and the ladder above it shows the state each state line moves to. Re-record with
`python3 -I site/record.py` when the session engine or the toy protocol changes;
`build.py` fails when the recording no longer shows the seven state moves the page
describes, when the event log on the page differs from it, or when the text behind the
first screen is no longer in `scapegoat/core/session.py`. Without JavaScript or with
reduced motion the page shows the link established again after the simulator restarts.
