# SentinelAI hackathon release

November 27, 2026 · Release for the November 28 hackathon.

## Automatic threat collection update

The companion ZIPs are published locally under `.runtime/automatic-threat-collection/release/`. The tagged hackathon artifacts remain available in their original folder. The models, thresholds, extension identity and Gmail OAuth configuration match that release.

The backend initializes history and threat storage independently. Their defaults are `backend/sentinel_ai.db` and `backend/sentinel_threats.db`. The threat migration adds `samples.risk_index`, `samples.indicators`, `samples.model_version` and a per-database `collection.dedup_key`. Older rows and approvals are retained. The old manual opt-in is reset once so users choose whether to enable automatic collection. New automatic rows start pending and unlabelled.

Automatic collection occurs after an existing suspicious verdict. It saves numeric features and non-identifying metadata. Email deduplication uses a keyed fingerprint of normalized input. URL deduplication ignores queries and fragments. Webpage deduplication also considers the bounded observations. Exact wording changes may produce another sample. Offline scans report collection unavailable and have no replay queue.

**Settings → Threat review** controls the global switch, review actions and approved numeric export. Webpage collection applies to the existing webpage analysis API. The extension does not automatically inspect arbitrary tab contents. The macOS verification ran 87 Python tests and 11 Node tests. The installed build replayed 3,106 labelled fixtures with matching Python verdicts and scores. Synthetic Gmail, the web review and export controls, both database failures and recovery, and offline restart passed. Live Gmail and Windows were outside this verification.

## Signing-key rotation and publication status

The old private Chrome signing key was committed in `1cb01ab`. Its public half matched the previous release's extension ID. The local copy is quarantined in an ignored directory with restricted permissions. This unpacked release uses a freshly generated public identity. No corresponding private key was saved. The loopback API derives the accepted origin from the new manifest and rejects the retired ID.

The public archives ship without the old Google OAuth client. The Gmail overlay and compose checks retain their local workflow. The optional account-connected inbox requires a new public OAuth client registered for the new ID. The project owner still needs to retire the old Google client and review its grants. See the [installation guide](INSTALL.md) for the setup.

The old key and a historical SQLite file remain reachable in existing Git history. The tag is for local use. Before any push or publication, coordinate retirement of the old Chrome identity, OAuth cleanup and handling of historical Git copies with the repository owner and collaborators. A history rewrite, if approved separately, can change commit and tag hashes. [GitHub sensitive data removal](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)

The release retains the existing local TF-IDF email classifier, its contextual rule set, and the URL model. The tuned models remain research artifacts. A comparison of 19 word, character, and structural variants is available with its operating points and confusion matrices. [Model evaluation](docs/release-model-evaluation.json)

The corrected production policy caught 3 of 88 phishing emails and flagged 0 of 87 legitimate emails in the recurring manual benchmark. It missed all 19 phishing samples in the original short benchmark. The best fit selected on validation was capped character 3–5 TF-IDF with source weights. It found 59 of 88 manual phishing emails while flagging 71 of 87 legitimate emails. On the short benchmark it found 19 of 19 and flagged 30 of 74 legitimate messages. It also flagged 6 of 15 benign authentication templates and 3 of 5 transaction templates. The favorable result on the prior archive/SMS set, 135 of 145 phishing with 1 false alert in 200 benign messages, used dissimilar source collections for the two classes. No additional independent, representative mailbox dataset was available.

The November 25 structural baseline reached 51.1% recall with 4.6% false positives on manual mail. The new capped structural model reached 46.6% and 5.7%. The character model's context-corroborated caution overlay recovered two additional manual phishing alerts with zero manual false positives and missed all 19 short phishing examples. The shipped lexical model alone flagged 70 of 88 phishing and 66 of 87 legitimate examples on manual mail. The deployed policy blocked 67 of those phishing and all 66 legitimate flags. Of those, 65 phishing and all 66 legitimate examples lacked an independent medium- or high-severity marker. Increasing the raw score’s weight alone would increase false alerts from this source.

## Repository inventory

| Category | Representative files | Release handling |
|---|---|---|
| Runtime | Python API, SQLite schema, privacy validation, `extension/src`, brand assets, two active model files and packaged worker parameters | Included with their required resources. |
| Development | npm lockfile, pinned Python requirements, build scripts and startup scripts | Included. `webpage_extractor.py` is standalone legacy code outside active API dispatch. Its pre-existing edit remains in the development tree. |
| Testing | Tests, fixtures and synthetic demo text | Included. Browser QA uses disposable profiles and databases. |
| Research and reproducibility | `training/`, reports and aggregate evaluation JSON | Source and aggregate results included. Five historical model artifacts and local research corpora and checkpoints remain in the development workspace. |
| Generated and temporary | Tracked virtualenv files, installed Node packages, old generated dist files, macOS metadata and bytecode | Removed from Git’s index with local copies preserved. Styling and official logo source files remain part of the project. |
| Sensitive | Local signing key, SQLite databases and backups, raw replay messages | Excluded. Git history contains an older private extension signing key and a historical scan database. History was preserved. The old key should be treated as exposed and excluded from future signing. |

The recoverable baseline includes a binary working-tree diff, an archive of the original untracked changes, the original Git status and production model hashes. It is kept privately under `.runtime/hackathon-release/baseline/`. Repository size measurements use both tracked file sizes and disk allocation since Git history and local research artifacts remain on disk.

## Functional fixes

The web Shield can scan a user-entered address. The extension Shield retains its active-tab workflow. The score pill and Gmail assessment show a risk index out of 100 and preserve the unscored state. The backend connection test reports missing models and unavailable SQLite history separately. Startup now uses an isolated virtualenv and retains cached dependencies across launches. The cross-platform Node build copies the manifest and Gmail stylesheet. Vite already packages the public logos and models.

See [installation](INSTALL.md), [demonstration](DEMO_GUIDE.md) and the [model handover](COLLABORATIVE_MODEL_REPORT.md).

## Package and verification

The release directory is `.runtime/hackathon-release/final/`. It contains `SentinelAI-Extension.zip`, `SentinelAI-Source.zip` and `SHA256SUMS.txt`. The extension ZIP contains a complete unpacked Chrome build. The source ZIP contains the shared React frontend, backend, two current models, public brand assets, lockfiles, startup scripts, tests and documentation. It omits generated dependency trees and the five legacy artifacts. The source build uses the package lock and verifies the output before distribution. The checksum file records exact sizes and SHA-256 hashes outside the archives.

The tracked file footprint fell from **108.60 MB** across 1,772 paths to approximately **44.73 MB** across 177 paths after removing 1,595 generated paths from the current index. Those counts exclude new untracked source files intended for later review. No Git history was rewritten. Local research, restored builds, and verification environments remain on disk. The two production Joblib artifacts and the packaged inference constants match their baseline SHA-256 hashes. The React and Gmail styles, branding and logos match the previous source.

Direct Python runtime pins and the npm lockfile were preserved. `requirements-test.txt` pins the browser harness dependency. The npm build now copies files with Node APIs. Startup isolates dependencies under `.runtime/app-venv`. Fixed local models are loaded before the server accepts requests, so a cold Python import does not consume the frontend's health timeout. Missing or corrupt models still report unavailable, and privacy continues independently. The rehearsal now verifies the optional review database after its first use.

The release was checked on macOS arm64 with Python 3.13, Node 26 and installed Chrome. The Windows scripts have source review only. The quality checks covered 82 Python and 11 Node tests, a clean npm build, synthetic web and installed Gmail workflows, 15 contextual authentication fixtures, compose redaction and undo, and backend recovery with unusable SQLite. The 3,106 labelled replays match Python on verdict and risk index. Private inbox data, live Gmail authorization, Windows execution and native Apple Messages were outside verification. The local React web app and Chrome extension are the release targets in this checkout.

The installed package hit zero HTTP requests in its 50 warm worker scans. Startup and warm scoring metrics, parity by cohort and artifact hashes are recorded alongside the ZIPs in the local verification ledger. Test messages and datasets are excluded from that ledger. The release is prepared locally under `v1.0.0-hackathon`.

Reproduce the lightweight model study from the development checkout with the previously documented screened local archives. The source ZIP contains the research runner and aggregate results. Reproduction also requires the local inputs and saved artifacts that were deliberately excluded.

```sh
PYTHONHASHSEED=42 OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
  PYTHONPATH=.runtime/handover/finetune-deps \
  python -m training.release_study .runtime/hackathon-release/model-replay.json \
  --legacy-csv /path/to/Phishing_Email.csv --public-seeds
```
