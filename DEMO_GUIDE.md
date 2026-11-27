# SentinelAI hackathon demonstration

## Prepare the demo

Use the tagged release ZIPs from the release directory. For automatic collection use the companion build in `.runtime/automatic-threat-collection/release/`. Follow the [installation guide](INSTALL.md) before going offline. Start the backend on `127.0.0.1:8000` and the web preview on `127.0.0.1:4173`. Use test data and an isolated SQLite database. For the live Gmail overlay, open a fictional message in an authorized demo account. The installed-browser rehearsal supplies a synthetic Gmail page and performs the same local scans and compose actions without account access.

## Five-minute demo

| Show | Fictional input and expected behavior | Needs |
|---|---|---|
| Web overview | Open `/popup.html` in the local web preview. Show Shield, Email Guard, Privacy and the history button. Shield waits for a URL. | Backend |
| Email screening | In Email Guard, paste “Please reply with the verification code sent to your device.” Expect **Suspicious** with the direct credential request marker. Paste “Hello.” Expect **Insufficient information** and no index. | Web backend or installed extension |
| Legitimate verification context | Paste “Your verification code is [CODE]. Enter the verification code on the sign-in page you already opened. If you did not try to sign in, change your password and enable two-factor authentication.” Expect **No clear indicators**. | Web backend or installed extension |
| URL assessment | Type `https://example.org/` into web Shield and scan the string. Compare it with `https://account.example.org@elsewhere.example/review`. The second contains user information before the actual hostname, which is displayed as a warning. Enter both as scanner inputs, without opening them. | Backend for web input |
| Gmail integration | Open a fictional school message and the fictional code disclosure example. An installed overlay classifies the opened message and shows its evidence on expansion. The optional inbox view uses Google sign-in. The synthetic browser rehearsal can show the overlay without fetching mail. | Internet for live Gmail. Local scanning remains available when the backend stops. |
| Privacy and redaction | Paste `Email: demo@example.org` in Privacy. Expect `Email: [EMAIL]`. In Gmail compose, use the synthetic draft below and open the pill. Deselect all, select only the email and choose **Redact selected**. Choose **Undo** to restore the draft. | Backend. Live Gmail also needs internet. |
| Scan history | Open **Scan & Audit History** after submitting a URL and an email. Show the scan type, timestamp, generic target and risk index. The original email body and URL are absent. | Backend with SQLite |
| Standalone inference | Stop the API you started and leave the web preview server running. In Chrome, open the local preview tab and then the extension popup. Shield checks the tab's local HTTP address. Email Guard still evaluates pasted text. The Privacy and History surfaces can report that their backend is unavailable. Restart the API and retry. | Installed extension for offline scoring |

### Demonstrate automatic threat review

Start with empty demo databases. On macOS, run the backend from the source directory with:

```sh
SENTINELAI_DB_PATH=.runtime/demo/history.db SENTINELAI_THREATS_PATH=.runtime/demo/threats.db bash start_backend.sh
```

1. Scan the fictional code disclosure message from the table while collection is off. The scan appears in history. **Threat review** stays empty.
2. Open **Settings → Threat review**, enable **Automatic collection**, and rescan. The review queue shows one pending email. Try the same input again to show deduplication. For an additional pending sample, scan the second URL from the table without opening it.
3. Mark the fictional email **Confirm phishing**, then **Approve for training**. Download the approved export and show the numeric features and human label. A mistaken alert can instead be confirmed legitimate. Delete the demo row or disable collection when finished.
4. Stop the backend and repeat the fictional email scan in the installed extension. The verdict remains available, and the details say collection is unavailable. This scan is never uploaded or saved later.

Compose rehearsal draft:

```text
Can you review the fictional class project?
Email: demo@example.org
I live in Flat 402 at Example Apartments near Sample Park in Hyderabad.
```

The broader synthetic email covers the full supported redaction-category demo. [Synthetic email](docs/privacy-demo-email.txt) · [Privacy walkthrough](docs/privacy-demo.md)

### Technical summary for judges

The React frontend also runs as a Manifest V3 extension. The Python API on loopback applies local phishing evidence and privacy validation, and saves metadata in SQLite. The browser worker carries the trained TF-IDF email weights and URL tree parameters. It can score both inputs without a model download. TF-IDF plus logistic regression fits a small local package, runs quickly in Chrome and keeps inference on the device. Contextual rules add concrete warning evidence, and an unfamiliar or sparse message can return insufficient information.

The screening index is an evidence summary on a 0–100 scale. On the 175-message manual development set the deployed policy caught 3 of 88 phishing messages and alerted on none of the 87 legitimate messages. Its conservative behavior misses many threats. The release comparison tested 19 lightweight variants. The validation-selected character model caught substantially more messages and also generated too many false alerts to ship. [Evaluation and limitations](RELEASE_REPORT.md)

### Repeatable rehearsal

From the extracted source root, install `requirements-test.txt` in the backend's app virtualenv. Stop your demo backend before invoking `tests.standalone_chrome`. It creates its own temporary databases, starts its own server on port 8000, and stops only that server.

```sh
source .runtime/app-venv/bin/activate
python -m pip install -r requirements-test.txt
python -m tests.demo_audit
python -m tests.browser_smoke extension/dist
python -m tests.standalone_chrome extension/dist
```

The two browser checks start disposable Chrome profiles and use sanitized fixtures. Live OAuth was outside the release rehearsal. The [installation guide](INSTALL.md) describes its setup.
