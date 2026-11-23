# SentinelAI for macOS

This Tauri 2 target uses its own React interface. It runs URL and email scans through the existing FastAPI service on the Mac.

## Run locally

Install [Rust](https://rust-lang.org/tools/install/), [Apple's Command Line Tools](https://v2.tauri.app/start/prerequisites/#macos) and Node.js 22 or later with npm. Set up the Python environment from the repository README.

From the repository root, start FastAPI in one terminal.

```sh
.runtime/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

In a second terminal from the repository root, start the native app.

```sh
cd mac-app
npm ci
npm run tauri dev
```

The Rust bridge uses the loopback address `127.0.0.1`. If FastAPI runs on a different port, set `SENTINELAI_API_PORT` to that port in the terminal that launches Tauri. The FastAPI service runs separately from the desktop app.

To build a local macOS app bundle, run this from `mac-app/`.

```sh
npm run tauri build -- --bundles app
```

Quit any running copy of SentinelAI after a build. Open `src-tauri/target/release/bundle/macos/SentinelAI.app` while FastAPI is running. Finder's Get Info shows version 0.2.0 for the redesigned release. Add `--debug` to the build command for a development bundle under `target/debug/`.

## Optional Messages monitoring

The URL and email scanners work without Full Disk Access. Monitoring starts off each time you launch SentinelAI. To enable it, open **Settings**, opt in to Messages monitoring, and use **Privacy Settings** to review SentinelAI's access in macOS. Return to the app and verify read access, then start monitoring. Verification checks whether this app can read the Messages database schema. Relaunch SentinelAI first if macOS asks. [Apple's guide to review or remove app access](https://support.apple.com/en-us/149699)

The Rust reader opens only `~/Library/Messages/chat.db` through a read-only SQLite connection. Starting skips existing messages. While monitoring, the reader processes new incoming plaintext rows and skips outgoing messages, attachments and message bodies that are unavailable as plaintext. The email phishing classifier has not been validated for SMS or iMessage. Its scores are estimates for review.

Message text goes to FastAPI over loopback for classification and is kept in memory. The desktop app stores results and a scan cursor in `messages-history.sqlite3` under its macOS Application Support directory. **Suspicious activity** shows phishing predictions and **Scan history** includes other outcomes. **Delete scan history** removes desktop Messages results and keeps the cursor to prevent rescans. It does not delete Apple Messages or web scanner history.

Use **Pause** to suspend polling after the current scan. **Resume** includes messages received while monitoring was paused. **Stop** ends the session. The next start skips messages received while monitoring was stopped. To remove the app's OS permission, use macOS Privacy & Security.

## Tests

```sh
npm run build
cargo test --locked --features custom-protocol --manifest-path src-tauri/Cargo.toml
```

The Rust tests use synthetic SQLite fixtures. For live acceptance testing, grant the app access yourself and check that a newly received test message appears in Scan history. Review permission denial and revocation separately with a test macOS account.
