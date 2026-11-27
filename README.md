# SentinelAI

SentinelAI runs a React browser preview and a Chrome Manifest V3 extension. The Python API performs scans on loopback. Chrome Identity can enable an optional read-only Gmail inbox view in a configured build. Local scans, classification, redaction and review require no API keys.

## Install and run

The [installation guide](INSTALL.md) covers the prebuilt Chrome ZIP and the source archive. Use the [demo guide](DEMO_GUIDE.md) for the rehearsed sequence and the [release report](RELEASE_REPORT.md) for model decisions and verification.

From a source checkout on macOS, run `bash start_backend.sh`. In a second terminal run:

~~~sh
npm --prefix extension ci
npm --prefix extension run build
npm --prefix extension run preview
~~~

Open [the React web app](http://127.0.0.1:4173/popup.html). Enter an address in Shield or use Email Guard, Privacy and History. To install the extension, select `extension/dist` from **Load unpacked** in `chrome://extensions`. Email and active-tab URL inference also run in the installed extension when the API is stopped. The web app, privacy and history require the API.

The web view and Chrome extension share the React frontend under `extension/src/popup`. This checkout contains those two entry points.

## Local API

| Endpoint | Inputs and behavior |
|---|---|
| POST /api/v2/scan-email | Accepts text, subject, sender, reply_to, labels, html and links. A link can be a string or a URL and label object. Returns an assessment, verified-in-input evidence excerpts, writing findings, privacy counts and per-link observations. Sender authentication is unavailable until a trusted integration supplies it. |
| POST /api/v2/scan-url | Accepts url. Returns structural evidence and a separate URL model observation. The response's destination omits user information, queries and fragments. |
| POST /api/privacy-redact | Accepts text, optional two-letter phone region, and selected finding IDs. Returns redacted text, counts, Unicode code point spans and masked findings. Use preview: true while editing or findings_only: true to return masked metadata only. |
| POST /api/scan-page | Accepts url and bounded numeric observations. The backend analyzes related indicators and returns an assessment. The browser must derive observations without reading form values or submitting content. |
| GET /api/v2/history | Returns metadata-only history. Optional query parameters include kind, limit and offset. |
| GET /api/health | Reports whether the loopback API and advisory model are available. |

Use preview: true for an assessment without a history write. Email and URL scans with enough evidence return finite complementary screening scores. Raw model estimates appear separately. The scores summarize evidence and model output. They do not measure the probability that a message or site is safe. Sparse email or unavailable models produce an explicit unscored state.

The Privacy tab and Gmail compose use the same loopback validator. The existing compose pill expands to review categories and choose individual occurrences. Review-only matches start unchecked. Redact all covers automatic matches and explicitly selected review items. Quotes and signatures stay out of scope unless the user includes them. The pill edits the draft locally and keeps the most recent undo in memory. The Privacy tab uses the existing preview and copy button for validated categories.

See the [privacy presentation guide and synthetic email](docs/privacy-demo.md) for the updated compose controls and address examples. Reload the rebuilt extension from `extension/dist`.

For the earlier tested bundle and scoring regression results, see the [scoring and privacy verification report](REGRESSION_REPORT.md).

The built-in English writing checks run locally. For broader coverage, start a standalone LanguageTool server on loopback and set SENTINELAI_LANGUAGETOOL_PORT before launching SentinelAI. The app masks URLs, addresses in email syntax, quoted lines, fenced code and conventional signatures before sending prose to that local service. It falls back to built-in rules if the service times out. [LanguageTool setup](https://dev.languagetool.org/http-server.html)

## Threat samples and retraining

The separate SQLite queue uses numeric features by default. Collection starts disabled. Send enabled: true to POST /api/threats/settings, then explicitly set collect_sample: true in a selected scan. For the email-only masked-text experiment, enable sanitized_text_enabled separately and set collect_text: true on the chosen scan. That mode stores a bounded set of recognized terms. The database omits free-form text and rejects masked samples with too little signal.

1. List the queue with GET /api/threats. Filter by kind, status and offset.
2. Use POST /api/threats/review with id and action to label phishing, legitimate, uncertain or rejected. Review the original evidence locally before assigning a label.
3. Use action approve to approve a confirmed label. Changing a label clears approval. Use action delete to delete a sample, or POST /api/threats/prune to remove expired samples according to retention_days.
4. Export approved rows with GET /api/threats/export. Use mode=text for approved masked email terms. Refresh older exports to include the approval status required by the training command.

Combine exports with verified historical examples and an independent holdout. Historical and holdout rows need a source or campaign group, a kind, a label of legitimate or phishing, and the same features schema. The text mode expects body and optional subject fields and masks them before training. Preserve the original artifact and use a fresh output directory for each candidate.

~~~sh
python -m training.train_reviewed_features --kind email \
  --approved /path/to/approved.json --historical /path/to/verified.json \
  --holdout /path/to/independent.json --output .runtime/candidates/email-01
~~~

Use --text with an approved masked-email export, or use --kind url or --kind webpage with numeric data. The command rejects shared fit and holdout groups and conflicting duplicates. It writes a candidate and evaluation report for manual review. Candidates require explicit integration after evaluation. The built-in URL advisory already has its own separate artifact.

## Verification

~~~sh
python -m unittest discover -s tests -v
python -m pip install -r requirements-test.txt
python -m tests.browser_smoke extension/dist
~~~

The browser smoke test uses a disposable Chrome profile, isolated SQLite databases and synthetic messages and forms. Set SENTINELAI_CHROME if Chrome is installed elsewhere. See the [audit and evaluation report](V2_REPORT.md) for measurements, baseline screenshots, security findings and frontend integration details.
