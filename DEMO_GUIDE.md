# SentinelAI hackathon demo

Use the local build, a disposable history database and the fictional examples below. Chrome sign-in is optional for the demo. The Gmail compose fixture uses the installed extension with synthetic drafts.

## Start the demo

From the repository root on macOS or Linux, install Python 3.11–3.13 and use Node 22 or newer.

```sh
python3 -m venv .runtime/demo-venv
source .runtime/demo-venv/bin/activate
python -m pip install -r requirements.txt websocket-client==1.8.0
mkdir -p .runtime/demo-data
SENTINELAI_DB_PATH="$PWD/.runtime/demo-data/history.db" \
SENTINELAI_THREATS_PATH="$PWD/.runtime/demo-data/threats.db" \
python -m backend.server 8000
```

Port 8000 is used by Gmail compose. If a previous SentinelAI session occupies it, stop that session from its terminal before starting the demo backend. Check it with `curl http://127.0.0.1:8000/api/health`. Both model flags should read `true`.

In a second terminal at the repository root, build from current source. The existing audited build in this workspace is **`.runtime/final-audit-extension/dist`**. This command rebuilds into **`extension/dist`** from a fresh install using the same source and lockfile.

```sh
npm --prefix extension ci
npm --prefix extension run build
python -m http.server 4173 --bind 127.0.0.1 --directory extension/dist
```

Open `http://127.0.0.1:4173/popup.html` for the React web preview. To use the extension, open `chrome://extensions`, enable **Developer mode**, and choose **Load unpacked** with the build folder you just prepared. Turn off any older copy for this session and refresh open Gmail tabs after reloading. Install and build before going offline.

## Presentation sequence

1. **Email Guard.** Paste “Let's meet at the library after school. Bring the science notes.” It returned “No clear phishing indicators detected.” Try “Hello.” to show “Insufficient information” and the absent score. The score on fuller text is a screening index.
2. **Evidence and URLs.** Run the rehearsal below. The phishing fixture asks for a password, uses different sender and Reply-To domains, and displays a link label that differs from its destination. The URL stage analyzes example-domain strings locally. The HTTPS example received model caution in rehearsal, while the misleading address produced a stronger warning. Talk through the evidence and avoid opening the supplied links.
3. **Grammar.** Point out the built-in writing finding on the phishing sample. Spelling alone is weak evidence. The rehearsal also shows which alert markers came from the subject, sender and link.
4. **Privacy.** Paste the all-category demo email into the Privacy tab. Copy the redacted preview. In Gmail compose, open the pill, choose **Deselect all**, check just the address and choose **Redact selected**. Use **Undo**, then **Redact all**. The 16-category draft and Undo passed in installed Chrome. In a second draft the invalid Aadhaar and ambiguous phone examples remain after one-click bulk redaction unless you select them. [Synthetic email](docs/privacy-demo-email.txt) · [Privacy and address examples](docs/privacy-demo.md)
5. **Dynamic scam fixture.** The browser smoke test inserts a synthetic local overlay and observes the backend response change. The rehearsal shows four benign page situations and three suspicious situations through the page endpoint. This is a fixture demonstration of the page engine. The installed extension has no arbitrary-tab observation collector.
6. **Threat review.** The rehearsal starts with collection disabled, opts in, submits one synthetic sample, confirms the label, approves it, and prints the approved numeric features. The export is empty before approval. This path runs through the local API.

## Rehearse offline

```sh
source .runtime/demo-venv/bin/activate
python -m tests.demo_audit
python -m unittest discover -s tests
node --test tests/gmail_api.test.mjs
python -m tests.browser_smoke extension/dist
```

Use `.runtime/final-audit-extension/dist` as the browser-test argument when using the prepared audit bundle. The rehearsal starts its own random loopback port and creates temporary databases. The browser smoke test uses disposable Chrome and a local synthetic compose editor. It substitutes the extension messaging transport, so it can run offline without a Google account. Live Gmail sign-in needs connectivity, an authorized test account and the existing Google Cloud extension-ID registration. Use the offline rehearsal if sign-in is unavailable.
