# Mochurin WaSeda — Malware Behavior Trainer *(working title)*

An educational web app for **MWS Cup 2026** (team Mochurin WaSeda). It walks a learner
through **what a piece of malware does, one stage at a time** — observe the behavior,
answer a quiz before advancing, then see the explanation — and finishes with a
**MITRE ATT&CK kill-chain recap**. Friendly, brilliant.org-style, with a dark theme.

## Safety first
This trainer **never runs malware.** Lessons are built from pre-captured sandbox
behavior or clearly-labelled **synthetic** examples stored as JSON. Nothing is executed,
downloaded, or detonated on your machine, and the MWS dataset is never bundled or run.

## Run it
No install needed — it's a static site.
```bash
cd MWS_MochurinWaSeda
python3 -m http.server 8000
# open http://localhost:8000
```

## How lessons work
Each lesson is a JSON file in `data/lessons/` (see `lesson-01.json`). A lesson has stages
(surface → launch → recon → persistence → exfiltration), each with observed **events**
(tagged with ATT&CK techniques) and a **quiz**, plus a **recap** kill-chain. Add a lesson
by dropping a new JSON file in and listing it in `data/lessons/index.json`.

## Optional: real behavior traces (advanced, not required)
The app ships working with synthetic lessons. To build a lesson from a *real* sample's
behavior **without running anything locally**, look the sample up **by hash** on a cloud
sandbox and turn its report into a lesson JSON:
- **VirusTotal** free public API (hash lookup; 4 req/min, 500/day). Needs your own free API key.
- Set the key in your environment only — **never commit it**. See `js/integrations.js`.
- **Do not upload MWS dataset samples** anywhere (redistribution terms). Hash lookup only.

## Project layout
```
index.html          shell
styles/design.css   design system (dark + light)
js/                 app, router, theme, data, home, player, quiz, recap, integrations
data/lessons/       lesson JSON + index.json
docs/               BUILD-CONTRACT.md, original-concept.png
```
