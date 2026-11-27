# Install and verify SentinelAI

Install Python 3.11–3.13, Node.js 22 or later, and Google Chrome. Run the commands from the repository root.

## Start the backend

On macOS:

```sh
bash start_backend.sh
```

On Windows, run `start_backend.bat` from Command Prompt. The startup script creates an isolated virtual environment and installs the pinned Python dependencies on first run. Check [backend health](http://127.0.0.1:8000/api/health) for model and database availability.

## Build and load Chrome

```sh
npm --prefix extension ci
npm --prefix extension run build
```

1. Open `chrome://extensions`, enable **Developer mode**, then choose **Load unpacked** and select `extension/dist`.
2. After a rebuild, click **Reload** on the installed extension and refresh any open Gmail tabs. If Chrome has a copy loaded from another folder with the same ID, remove that copy before loading `extension/dist`.
3. To use the web preview, run `npm --prefix extension run preview` and open [the local popup](http://127.0.0.1:4173/popup.html).

The installed extension can screen email text and active-tab URLs while the backend is offline. The web preview, privacy checks, Gmail compose redaction and history use the local backend.

## Authorize Gmail

In a Chrome profile signed into your Google account, open **Email Guard → Sign in with Google**, grant read-only Gmail access, and choose **Scan Inbox**. The standard build carries the team's public OAuth client ID. The project owner manages test users if the app is in Google Cloud Testing. Managed Workspace accounts may also require administrator approval. [Google Auth Platform audience](https://support.google.com/cloud/answer/15549945)

## SQLite and threat review

The backend uses `backend/sentinel_ai.db` for scan and privacy history and `backend/sentinel_threats.db` for the threat review queue. Set `SENTINELAI_DB_PATH` and `SENTINELAI_THREATS_PATH` to distinct files for a demo or development session.

Automatic collection starts disabled. Enable it in **Settings → Threat review**. Disabling collection stops new samples while saving prior reviews. The installed scanner still assesses supported inputs offline, when collection is unavailable.

## Regression checks

Use the environment created by the startup script. On macOS:

```sh
source .runtime/app-venv/bin/activate
python -m pip install -r requirements-test.txt
python -m unittest discover -s tests
node --test tests/*.test.mjs
python -m tests.demo_audit
python -m tests.browser_smoke extension/dist
python -m tests.standalone_chrome extension/dist
```

The last check requires port 8000 to be free. Both browser checks use disposable Chrome profiles, synthetic fixtures and isolated databases. Set `SENTINELAI_CHROME` if Chrome is installed at a custom path.
