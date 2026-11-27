# SentinelAI hackathon release

November 27, 2026 · Release for the November 28 hackathon.

## Automatic threat collection update

This report records the hackathon checks and model decisions. Build the current extension from source using the [installation guide](INSTALL.md).

The backend initializes history and threat storage independently. Their defaults are `backend/sentinel_ai.db` and `backend/sentinel_threats.db`. The threat migration adds `samples.risk_index`, `samples.indicators`, `samples.model_version` and a per-database `collection.dedup_key`. Older rows and approvals are retained. The old manual opt-in is reset once so users choose whether to enable automatic collection. New automatic rows start pending and unlabelled.

Automatic collection occurs after an existing suspicious verdict. It saves numeric features and non-identifying metadata. Email deduplication uses a keyed fingerprint of normalized input. URL deduplication ignores queries and fragments. Webpage deduplication also considers the bounded observations. Exact wording changes may produce another sample. Offline scans report collection unavailable and have no replay queue.

**Settings → Threat review** controls the global switch, review actions and approved numeric export. Webpage collection applies to the existing webpage analysis API. The extension does not automatically inspect arbitrary tab contents. The macOS verification ran 87 Python tests and 11 Node tests. The installed build replayed 3,106 labelled fixtures with matching Python verdicts and scores. Synthetic Gmail, the web review and export controls, both database failures and recovery, and offline restart passed. Live Gmail and Windows were outside this verification.

## Signing-key rotation and publication status

The old private Chrome signing key first appeared as `extension/dist.pem` in `1cb01ab`. The current manifest uses the replacement public key and its shared Chrome OAuth client. The loopback API accepts the replacement origin and rejects the retired ID. The cleanup removed the obsolete local key copy after verifying that it matched the historical Git blob.

The key and nine versions of `backend/sentinel_ai.db` remain reachable in Git history. The key-introducing commit is an ancestor of the local `origin/main` tracking ref. The historical databases contained up to 552 scan records and one privacy audit. Aggregate checks found email-like values and URLs with query strings in historical previews. Treat those previews as potentially private. The two active databases are ignored and remain on this machine.

Before publishing:

1. Have the Google Cloud project owner disable or delete the old Chrome OAuth client, review or revoke its existing grants, and retire any extension distribution that used the old key. Keep the current shared client registered for the replacement extension ID.
2. Restrict access to copies of the historical SQLite snapshots and determine who had access. Review the affected previews privately for data that needs notification or credential rotation. Keep current databases and necessary backups private.
3. After separate approval, coordinate a history cleanup covering both paths and affected branches, tags and refs. Check cached pull-request views, forks, clones and backups, and ask GitHub Support about eligible cached references. Have teammates re-clone or rebase onto the cleaned history. Verify the affected blobs are no longer reachable before publishing the cleaned repository. [GitHub sensitive data removal](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)

## Model evaluation

The release retains the existing local TF-IDF email classifier, its contextual rule set, and the URL model. The tuned models remain research artifacts. A comparison of 19 word, character, and structural variants is available with its operating points and confusion matrices. [Model evaluation](docs/release-model-evaluation.json)

The corrected production policy caught 3 of 88 phishing emails and flagged 0 of 87 legitimate emails in the recurring manual benchmark. It missed all 19 phishing samples in the original short benchmark. The best fit selected on validation was capped character 3–5 TF-IDF with source weights. It found 59 of 88 manual phishing emails while flagging 71 of 87 legitimate emails. On the short benchmark it found 19 of 19 and flagged 30 of 74 legitimate messages. It also flagged 6 of 15 benign authentication templates and 3 of 5 transaction templates. The favorable result on the prior archive/SMS set, 135 of 145 phishing with 1 false alert in 200 benign messages, used dissimilar source collections for the two classes. No additional independent, representative mailbox dataset was available.

The November 25 structural baseline reached 51.1% recall with 4.6% false positives on manual mail. The new capped structural model reached 46.6% and 5.7%. The character model's context-corroborated caution overlay recovered two additional manual phishing alerts with zero manual false positives and missed all 19 short phishing examples. The shipped lexical model alone flagged 70 of 88 phishing and 66 of 87 legitimate examples on manual mail. The deployed policy blocked 67 of those phishing and all 66 legitimate flags. Of those, 65 phishing and all 66 legitimate examples lacked an independent medium- or high-severity marker. Increasing the raw score’s weight alone would increase false alerts from this source.

## Repository inventory

| Category | Representative files | Current location |
|---|---|---|
| Runtime | Python API, SQLite schema, privacy validation, `extension/src`, brand assets and model files | Checkout. Two Python production models and the offline browser weights remain active. |
| Development | Lockfiles, build and startup scripts | Checkout. Vite outputs the installed extension to `extension/dist`. |
| Testing | Tests, fixtures and synthetic demo text | Checkout. Browser QA uses disposable profiles and databases. |
| Research | `training/`, evaluation reports, datasets and model candidates | Research code and aggregate reports remain in the checkout. Historical model files and local research inputs are in the private archive beside the checkout. |
| Private data | SQLite databases, backups and raw research replays | Active databases are ignored in the checkout. Backups and replays remain private. |

## Functional fixes

The web Shield can scan a user-entered address. The extension Shield retains its active-tab workflow. The score pill and Gmail assessment show a risk index out of 100 and preserve the unscored state. The backend connection test reports missing models and unavailable SQLite history separately. Startup now uses an isolated virtualenv and retains cached dependencies across launches. The cross-platform Node build copies the manifest and Gmail stylesheet. Vite already packages the public logos and models.

See [installation](INSTALL.md), [demonstration](DEMO_GUIDE.md) and the [model handover](COLLABORATIVE_MODEL_REPORT.md).

## Historical verification

Direct Python runtime pins and the npm lockfile were preserved. `requirements-test.txt` pins the browser harness dependency. The npm build now copies files with Node APIs. Startup isolates dependencies under `.runtime/app-venv`. Fixed local models are loaded before the server accepts requests, so a cold Python import does not consume the frontend's health timeout. Missing or corrupt models still report unavailable, and privacy continues independently. The rehearsal now verifies the optional review database after its first use.

The release was checked on macOS arm64 with Python 3.13, Node 26 and installed Chrome. The Windows scripts have source review only. The quality checks covered 82 Python and 11 Node tests, a clean npm build, synthetic web and installed Gmail workflows, 15 contextual authentication fixtures, compose redaction and undo, and backend recovery with unusable SQLite. The 3,106 labelled replays match Python on verdict and risk index. Private inbox data, live Gmail authorization, Windows execution and native Apple Messages were outside verification. The local React web app and Chrome extension are the release targets in this checkout.

The installed extension made zero HTTP requests in its 50 warm worker scans. Startup and warm scoring metrics, parity by cohort and artifact hashes remain in the local verification ledgers.

## Archived research

The local owner-only folder `../SentinelAI-research-archive-2026-11-27` has an inventory, model files under `models/`, and datasets, checkpoints and screenshots under `research/`. Verification ledgers and private backups have separate folders. To run the legacy URL check, pass the archived model directory explicitly. The historical comparison command accepts the same `--legacy-models` option.

```sh
python -m training.test_url_model_v2 --legacy-models ../SentinelAI-research-archive-2026-11-27/models
```

For other historical studies, use the input options in `training/` and the archived research files. Older runners that assume `.runtime/` paths can be reproduced in a separate research checkout by restoring the matching subdirectories there.
