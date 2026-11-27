# SentinelAI

SentinelAI is a Chrome extension and local web app for phishing screening and privacy redaction. The Python backend runs on loopback. The installed extension can screen email text and active-tab URLs offline.

## Run locally

Start the backend with `bash start_backend.sh` on macOS or `start_backend.bat` on Windows. In a second terminal, from the repository root:

```sh
npm --prefix extension ci
npm --prefix extension run build
```

In Chrome, open `chrome://extensions`, enable **Developer mode**, and load `extension/dist` unpacked. The optional Gmail Inbox Scanner uses the team's shared read-only OAuth client. For the web preview, run `npm --prefix extension run preview` and open [the local popup](http://127.0.0.1:4173/popup.html).

See [installation and verification](INSTALL.md) or the [demo walkthrough](DEMO_GUIDE.md).

## Local data

- Privacy Guard and Gmail compose validate and redact selected findings. The backend keeps scan metadata in a local SQLite database.
- Automatic threat collection starts off. Enable it in **Settings → Threat review** to collect numeric features from eligible scans in a separate SQLite database. Training export requires a human label and explicit approval.
- Risk indexes summarize the observed evidence and model output. A scan can abstain when there is insufficient information.

## Project layout

| Path | Role |
| --- | --- |
| `extension/src/`, `extension/public/` | React popup, Gmail integration, offline models and official assets |
| `backend/`, `models/` | Loopback API, both SQLite stores and the two production Python models |
| `tests/`, `training/` | Regression tests, synthetic fixtures and research tools |
| `docs/` | Evaluation data and privacy demo material |

See the [model handover](COLLABORATIVE_MODEL_REPORT.md), [regression results](REGRESSION_REPORT.md), and [historical security and evaluation notes](RELEASE_REPORT.md). The archive location and reproduction notes are recorded in the historical report.
