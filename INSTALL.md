# Install SentinelAI

The two archives are independent. Use the extension archive for local email and URL screening in Chrome. Use the source archive for the React web app, local API, SQLite history and privacy checks.

## Install the Chrome extension

1. Extract `SentinelAI-Extension.zip`.
2. In Chrome, open `chrome://extensions`, enable **Developer mode**, and choose **Load unpacked**.
3. Select the extracted **SentinelAI-Extension** folder containing `manifest.json`.
4. Disable or remove the old SentinelAI extension, then pin the replacement and reload any open Gmail tabs. The unpacked release uses a new extension ID.

Email Guard and the active-tab URL Shield use packaged model weights when the backend is unavailable. Their verdicts can include **No clear indicators**, **Caution**, a high-risk warning, or an unavailable score. The displayed risk index is on a 0–100 scale. It summarizes model output and observed evidence. It does not estimate the probability of harm or safety. Privacy checks, compose redaction and saved history require the loopback API at port 8000.

## Start from source on macOS

Install Python 3.11–3.13 and Node.js 22 or later before extracting `SentinelAI-Source.zip`. Open Terminal in its `SentinelAI` folder and run:

```sh
bash start_backend.sh
```

The first run creates an isolated environment and installs the pinned Python dependencies. In a second terminal in the same folder:

```sh
npm --prefix extension ci
npm --prefix extension run build
npm --prefix extension run preview
```

Open [the web app](http://127.0.0.1:4173/popup.html). The web app and Chrome extension share the React source. You can load the local `extension/dist` in Chrome instead of the prebuilt archive.

## Start from source on Windows

Install Python 3.11–3.13 and Node.js 22 or later. From Command Prompt in the extracted `SentinelAI` folder:

```bat
start_backend.bat
```

Use a second Command Prompt for the same three npm commands above. Open `http://127.0.0.1:4173/popup.html`. The build uses Node for file copying and the archives use portable file paths. The fresh installation was verified on macOS arm64. The Windows startup path was reviewed but has no runtime verification.

### Gmail and local data

The Gmail overlay uses your existing Gmail tab and its compose panel uses the local backend for privacy checks. The optional Google-connected inbox view in the popup requires a configured build. The public archives omit that configuration.

1. In Google Cloud, enable the Gmail API and People API for the project. Configure the OAuth consent screen and authorize the intended test account.
2. Create a **Chrome Extension** OAuth client for the new unpacked ID **`ljhaekkkeoaajonchnhaaepfcelccbpd`**. Confirm the actual ID under `chrome://extensions` before registering it.
3. Set `SENTINELAI_GOOGLE_CLIENT_ID` to the new public client ID and run `npm --prefix extension run build` from source. On macOS, prefix the build command with `SENTINELAI_GOOGLE_CLIENT_ID="YOUR_PUBLIC_CLIENT_ID"`. In Windows Command Prompt, run `set "SENTINELAI_GOOGLE_CLIENT_ID=YOUR_PUBLIC_CLIENT_ID"` first.
4. Reload the extension, refresh Gmail and test sign-in with the authorized account. Keep the configured build separate from the public archives. [Chrome OAuth setup](https://developer.chrome.com/docs/extensions/how-to/integrate/oauth)

The project owner should retire the Google OAuth client bound to the old extension ID and review or revoke its existing grants. Use a fresh Chrome Web Store item and its public key if the team later publishes a signed distribution. Register OAuth for that item's ID and rebuild the backend source manifest and extension with the same public key. [Chrome extension identity](https://developer.chrome.com/docs/extensions/reference/manifest/key)

### SQLite and threat review

Startup initializes both databases when their paths are writable. Defaults relative to the source folder are `backend/sentinel_ai.db` for scan and privacy history, and `backend/sentinel_threats.db` for the separate review queue. Override them with `SENTINELAI_DB_PATH` and `SENTINELAI_THREATS_PATH` before starting. Use distinct files. Use an isolated demo directory and fictional inputs for a rehearsal.

Open **Settings → Threat review** in the web app or installed popup. The global switch starts off, including once after upgrading from the earlier manual collection workflow. The queue shows review counts and pending samples. Only confirmed samples can be approved, and the export contains approved numeric rows. Turning off collection stops new samples. Existing rows remain available for review or deletion.

With the API offline, Chrome still assesses emails and URLs. The result details report that collection is unavailable. Offline inputs are never queued. After reconnecting, subsequent eligible scans can be collected again.

To inspect the SQLite files using the macOS SQLite CLI, use read-only access. Change the file names below if you set overrides.

```sh
sqlite3 -readonly backend/sentinel_ai.db 'SELECT scan_type, risk_level, created_at FROM scan_history ORDER BY id DESC LIMIT 10;'
sqlite3 -readonly backend/sentinel_threats.db 'SELECT kind, status, label, risk_index, created_at FROM samples ORDER BY id DESC LIMIT 10;'
```

### Troubleshooting

- Check [backend health](http://127.0.0.1:8000/api/health). It shows connection, model and history availability separately. The web app and in-page overlay use loopback port 8000 by default.
- If 8000 or 4173 is occupied, stop the service you started on that port and retry. Inspect other services before closing them.
- If Chrome reports a missing manifest, select the inner folder that contains `manifest.json`. Keep its `models/` and `logos/` folders alongside it.
- With the backend stopped, use the installed extension for email and URL screening. The web preview, privacy and history need the backend. After restarting it, wait a few seconds for the worker to check availability again.
- First-time Python and npm installs require network access unless both dependency caches already contain the packages. The prebuilt extension ZIP can be installed while offline.
- Google access errors usually require checking the OAuth client ID, extension ID, Gmail API and OAuth consent test-account list. The release did not use a live Gmail account.

See the [demo guide](DEMO_GUIDE.md) and [release verification](RELEASE_REPORT.md).
