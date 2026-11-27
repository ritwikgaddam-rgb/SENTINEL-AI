# SentinelAI V2 audit and verification

## Protected frontend baseline

Work started on main at 63287d9, the revert that restored the frontend from 8a4d235. The complete extension and official logo trees matched that design commit. This checkout has one React interface, used both as a browser preview and as the Chrome popup. The earlier native application and a separate website source tree are outside this checkout.

The protected inventory includes:

- extension/popup.html, src/theme.css, src/popup/Popup.css and the source, root and bundled Gmail overlay CSS.
- The React entry point, App and every component under src/popup/components, plus gmailApi.js.
- Gmail and background scripts, the Manifest V3 configuration, Vite and package files, the packaged bundle and both app and shared logo directories.

Before source edits, I captured the actual installed unpacked extension and browser preview in disposable Chrome with a synthetic Gmail page and fixed API fixtures. The inventory recorded 228 protected file hashes and the complete Git status for the extension and logo paths. It excludes dependency files and signing material from the content hashes. Git also checked those tracked paths. The ignored build-v2 directory contains the earlier interface and was outside the visual comparison. The tracked extension/dist directory is the restored reference.

The isolated rebuild used the existing Vite command. Its contents matched the restored dist directory byte for byte. Chrome screenshots were pixel-identical in all ten scene pairs at the same viewport sizes. The popup was 390×580, Gmail was 960×640 and the browser preview was 800×680. The test exercised the navigation transition, theme switches, hover, loading animation, clipboard callback, history, settings, Gmail warning banner, audit drawer and compose redaction. It froze repeating animations at a fixed frame for pixel comparison. Chrome used synthetic data and a deterministic offline font fallback.

The before and after screenshots and protected inventory are in the private local research archive under `research/frontend-baseline-63287d9`. [Archive inventory and location](RELEASE_REPORT.md#archived-research)

## Established model and data issues

The original email artifact is a word unigram/bigram TF-IDF pipeline with Logistic Regression. The checked-in training script maps Safe Email to 0 and Phishing Email to 1, and the saved estimator reports classes in that order. The vectorizer lowercases words and omits one-character tokens. Its intercept is approximately −0.0617, about 48.46% class 1 for a zero-feature input. Recognized words drive many greeting errors. The merged archive referenced in the script is cleaned and written separately. The model fit in that script uses the labelled Phishing_Email.csv input. The other SMS artifact predicts ordinary spam, a separate task.

The original email training CSV and parquet are unavailable in this checkout, so training-source proportions, duplicate leakage and individual label provenance could not be verified row by row. The learned features reported earlier, such as Enron, Vince, you and your, support a shortcut-learning explanation. The original script uses a random row split. Its metrics cannot establish performance on new source domains or campaigns.

The saved URL v2 random forest uses class 0 for phishing and nine ordered inputs. The order retains the historical NoOfDegitsInURL spelling. Its training script fits recomputed URL features with the published labels. Comparing those recomputed features with the PhiUSIIL release gave 20.63% agreement for URL length, 0% for letter count and 98.66–100% for the other seven. Mixing the published counts with runtime counts would misalign inference. The original labelled benign slice also consisted of HTTPS www root addresses, a structural shortcut for ordinary modern URLs with paths and searches. [PhiUSIIL publisher](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)

## Email and privacy improvements

The V2 API uses contextual evidence and withholds numeric scores. Direct credential requests, deceptive link destinations and corroborating indicators can trigger a suspicious result. Generic words, writing mistakes and sensitive data in the body do not trigger phishing warnings. Sparse evidence produces an explicit abstention. These rules have limited phishing recall, measured below.

Analysis handles subject and body, From display name and sender domain, Reply-To domains, labels, URL text and HTML anchors. It identifies sender and URL lookalikes, compares displayed and actual destinations, removes URL credentials and query values from returned destination strings and collects an advisory model observation for each distinct link. It does not visit link destinations. Gmail authentication remains unavailable until a trustworthy integration supplies it. The built-in grammar checker covers limited spelling, agreement, repeated words, capitals and punctuation. An optional LanguageTool client uses loopback with timeouts. Tests cover Unicode offsets and failure fallback through a mocked local service. This Mac had no Java runtime for a live LanguageTool test.

| Privacy coverage | Validation and review |
|---|---|
| Email addresses and UPI IDs | Email syntax and an explicit UPI or VPA label. |
| Indian and international phone numbers | phonenumbers validation, calling context and review for plausible unlabelled numbers. |
| Aadhaar | Verhoeff checksum and contextual labelling. |
| Credit and debit cards, IBAN | Luhn and IBAN validation with contextual review. |
| Bank accounts, IFSC, PAN, passports and US SSNs | Format and surrounding labels. Unlabelled formatted SSNs go to review. |
| Residential and mailing addresses | Labelled fields, a local CRF address parser for structured US addresses, and review of other supported street and PO box patterns. |
| Postal codes | Contextual Indian PIN, US ZIP, Canadian, UK and other supported formats. |
| Explicit passwords, API keys and authentication tokens | Label and format checks, quoted passphrases, Bearer tokens and JWT-shaped tokens. |

Automatic and manually approved redactions use spans with Unicode code point offsets. Counts refer to values actually replaced. Uncertain matches remain available for review. Regression coverage includes all 16 categories, valid and invalid checksums, ordinary order and transaction identifiers, adjacent prose, repeated values, multiline formatting and Unicode. A broader accuracy estimate would require labelled privacy examples across languages and countries. [Local US address parser](https://pypi.org/project/usaddress/)

### Reported false positives

The old column is the saved model's direct phishing estimate. Earlier manually reported safety percentages used the application's previous scoring formula.

| Input | Old phishing estimate | V2 outcome |
|---|---:|---|
| Hello | 88.70% | Insufficient information |
| How are you doing today | 70.38% | Insufficient information |
| Hey how are you what are you doing | 78.15% | Insufficient information |
| Never share your password or OTP with anyone | 70.73% | Insufficient information |
| Please send me the homework when you finish | 41.96% | Insufficient information |
| I has completed my homework yesterday | 29.80% | Insufficient information, plus a grammar finding |
| Here is the Python documentation: https://docs.python.org/3/ | 26.48% | No clear phishing indicators detected |
| A school meeting and project review notice | 11.55% | No clear phishing indicators detected |
| Please reply with the verification code sent to your device. | 69.88% | Suspicious |

## Model evaluation

### Email

The source-held-out benchmark uses Apache SpamAssassin ham and labelled Nazario phishing mail. Separate archives provided the fit and validation cohorts. Ordinary spam was excluded. Normalized exact text and matching opening or closing template phrases stayed in one cohort. The final 175 English Manual seeds from PhishFuzzer were excluded from candidate fitting and calibration. They consist of 87 legitimate and 88 phishing examples and can include simulations. Candidate inputs use subject and body with URLs, email addresses and numbers normalized. The original pipeline receives the raw body. Legacy overlap cannot be completely ruled out because its fit rows are unavailable. [Apache corpus labels](https://spamassassin.apache.org/old/publiccorpus/readme.html) · [Nazario phishing corpus](https://monkey.org/~jose/phishing/) · [PhishFuzzer seed publication](https://github.com/DataPhish/PhishFuzzer)

The fit contains 2,042 legitimate and 629 phishing examples after exclusions. The validation cohort contains 1,388 legitimate and 319 phishing examples. The SVM used sigmoid calibration on validation and all candidates used a fixed 0.5 decision threshold.

| Classifier | Accuracy | Precision | Recall | F1 | FPR | FNR | Brier | Confusion TN/FP/FN/TP |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Original | 52.00% | 51.47% | 79.55% | 62.50% | 75.86% | 20.45% | 0.3091 | 21/66/18/70 |
| Word logistic regression | 44.00% | 43.59% | 38.64% | 40.96% | 50.57% | 61.36% | 0.3140 | 43/44/54/34 |
| Word and character logistic regression, balanced | 41.71% | 44.44% | 63.64% | 52.34% | 80.46% | 36.36% | 0.3542 | 17/70/32/56 |
| Word and character SVM, balanced and calibrated | 41.71% | 44.93% | 70.45% | 54.87% | 87.36% | 29.55% | 0.4593 | 11/76/26/62 |

A distinct authors' set of 100 real email and SMS examples gave the original model 38.96% FPR and 91.30% recall. Word logistic regression gave 36.36% FPR and 73.91% recall. Both combined-feature candidates reached 100% recall with 72.73% FPR. The 1,900 generated examples in that release were excluded. Early-2000s benign training mail still differs from newer messages and the phishing sources. The candidates remain offline. [Phishing validation email dataset and provenance](https://zenodo.org/records/23954793)

On the 175-message PhishFuzzer test, local evidence produced one false alert among 87 legitimate inputs. It flagged two of 88 phishing inputs, abstained on 12 and found no clear indicators in 74. It also abstained on one legitimate input. On the real email and SMS subset, it abstained on ten legitimate and one phishing message, flagged zero and missed the other 22 phishing messages. These figures measure evidence coverage. They show that the prototype cannot reliably screen an inbox on its own.

Original, word, combined logistic and calibrated SVM batch timings were 0.059, 0.071, 0.494 and 0.464 ms per message. The artifacts were 932,628, 462,859, 1,259,141 and 1,236,171 bytes respectively.

~~~sh
python -m training.compare_email_models /path/to/PhishFuzzer_emails_original_seed_v1.json \
  .runtime/candidates/email-source-01 \
  --fit-ham /path/to/20030228_easy_ham.tar.bz2 \
  --fit-ham /path/to/20030228_hard_ham.tar.bz2 \
  --fit-phishing /path/to/phishing-2019 --fit-phishing /path/to/phishing-2022 \
  --fit-phishing /path/to/phishing-2023 \
  --validation-ham /path/to/20030228_easy_ham_2.tar.bz2 \
  --validation-phishing /path/to/phishing-2024
~~~

[Measured email report and input hashes](.runtime/candidates/sentinel-v2-email-63287d9/evaluation.json)

### URL

The independent benchmark from the PhreshPhish URL-only metadata excludes every PhiUSIIL registrable domain and groups the remaining data by registrable domain. There were zero shared fit and holdout domain groups. The test contains 17,473 benign and 19,158 phishing addresses. The gradient-boosted candidate uses URL structure with query values excluded. It normalizes equivalent root paths and adds path depth, URL encoding and IDN features. [PhreshPhish primary dataset](https://huggingface.co/datasets/phreshphish/phreshphish)

| Classifier | Accuracy | Precision | Recall | F1 | FPR | FNR | Brier | Confusion TN/FP/FN/TP |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Original URL forest | 38.70% | 44.78% | 73.88% | 55.76% | 99.87% | 26.12% | 0.5977 | 23/17450/5005/14153 |
| Query-free candidate | 87.86% | 88.79% | 87.87% | 88.33% | 12.16% | 12.13% | 0.0894 | 15348/2125/2323/16835 |

The URL candidate is advisory because a 12.16% false-positive rate remains too high for an authoritative warning. It did not flag the tested Amazon India search, Flipkart root or YouTube search where the old artifact assigned 100% phishing probability. V2 returned Insufficient information on all three. Domain grouping cannot exclude every cross-domain campaign. Absolute rates apply to this cohort.

Batch inference measured 0.00582 ms per URL for the 22,137,849-byte original and 0.00104 ms for the 110,508-byte candidate. The rerun reproduced the advisory artifact byte for byte.

~~~sh
python -m training.compare_url_models /path/to/test_url_metadata.csv.gz \
  /path/to/phiusiil-complete.zip .runtime/candidates/url-01
~~~

[Measured URL report](.runtime/candidates/sentinel-v2-url-63287d9/evaluation.json)

## Page observations and threat review

The page API accepts bounded derived counts. It evaluates infection and intervention claims, prize and payment lures, impersonating overlays and credentials associated with a cross-host form. Separate form counts are insufficient to infer that a password form sends data externally. The test browser supplied numeric counts from a safe local DOM fixture, including a delayed overlay. The extension still needs a production observation sender. The runtime API performs no webpage fetches. The legacy standalone webpage extractor has an independent DNS check and HTTP lookup, so it should stay outside the API.

The threat database has four tables. Collection stores the numeric opt-in and retention setting. Samples stores the timestamp, type, exact normalized feature fingerprint, numeric features, assessment, schema version, review status and human label. Text policy stores separate consent. Sanitized samples stores bounded email terms linked to a sample and deleted with it. Unknown words and detected private spans are discarded, including from approved text exports. The masked representation is deliberately small and cannot replace full-text model training data.

The review endpoint supports human labels, correction, explicit approval and deletion. It exports only approved examples. Exact feature or masked-term fingerprints deduplicate. The training command checks conflicts, duplicates and independent source groups and creates isolated artifacts. Sparse feature vectors and the masked text representation can collapse different messages. No representative annotated webpage corpus was available for model training.

## Repository and data audit

The working database contained 404 rows when inspected read-only. There were 294 email and 110 URL records, with a sender metadata field in 294 records. The privacy-audit table was empty. Historical previews and metadata can contain sensitive material. The API omits them from responses and new records. The first browser smoke attempt reached the existing running backend and added one Gmail URL scan. I left all rows in place and blocked the live backend port for subsequent browser testing. Before approved cleanup, back up the database privately, scrub a copy while checking row counts and settings, then checkpoint and vacuum the approved scrubbed database. Removal from Git's index and removal from Git history are separate operations.

Git tracked 1,528 extension dependency paths, 572 legacy virtual environment paths, the original dist package, the runtime database and extension/dist.pem. I verified that the private file derives the current public manifest identity. Treat that key as exposed. The clean package directory excludes it. After approval, confirm the distribution channel and coordinate with the Chrome Web Store and Google Cloud owners. Plan the development or self-distributed identity and corresponding OAuth client registration, validate sign-in and upgrade behavior with an authorized test user, then retire the exposed material. Keep replacement private material outside the repository and coordinate any Git history remediation separately. [Chrome extension identity](https://developer.chrome.com/docs/extensions/reference/manifest/key) · [Chrome OAuth registration](https://developer.chrome.com/docs/extensions/how-to/integrate/oauth)

## Frontend handoff

The recorded frontend diff is empty. Each connection below can reuse the original styles and layout. It still requires approval before editing the protected code.

| Exact files | Integration requiring frontend code |
|---|---|
| extension/src/popup/components/PrivacyGuardTab.jsx, extension/src/popup/components/EmailScannerTab.jsx | Use the backend’s validated counts, review spans and redacted text for the existing copy actions. The current Privacy tab is client-only. The old Email Guard copy covers its three original categories. |
| extension/src/popup/gmailApi.js, extension/src/popup/components/EmailScannerTab.jsx | Send already available Gmail subject and label metadata and map available Reply-To and link information. Gmail authentication results require a trusted source. |
| extension/src/popup/App.jsx, extension/src/popup/components/ShieldStatus.jsx, extension/src/popup/components/EmailScannerTab.jsx, extension/src/popup/components/MarkersCard.jsx, extension/src/popup/components/HistoryModal.jsx | Use the evidence assessment and explanation as labels, remove the percent suffix for missing confidence and the offline numeric fallbacks, and present link and grammar findings in existing cards. The legacy adapter prevents a default red Shield result for unknown outcomes. Existing client wording can still overstate certainty. |
| extension/src/content/content.js | Send Gmail metadata where available, use text nodes for markers, and apply approved privacy spans without rewriting the draft's HTML. The backend already escapes fields for the legacy HTML renderer. |
| extension/src/background/background.js, extension/src/popup/components/SettingsModal.jsx, extension/src/popup/App.jsx, extension/manifest.json | Wire a user-triggered page observer and optional watch setting using the active tab, bounded numeric observations and the existing Shield and badge controls. Chrome needs the minimum permission for user-triggered script injection. |

Validate these connections with a consenting test Gmail account when the team approves the frontend work. Live OAuth, real Gmail data, production webpage watching and an actual system clipboard require manual testing.

## Work files and verification

This pass modified .gitignore, README.md, V2_REPORT.md, requirements.txt, privacy_detector.py, backend/assessments.py, backend/database.py, backend/server.py, backend/threats.py, training/compare_email_models.py, training/train_reviewed_features.py, tests/test_v2.py and tests/browser_smoke.py. The starting working tree also contained the modified runtime database and launcher, and the untracked URL advisory, URL benchmark and candidate artifact. The original model artifacts, signing material, branch and frontend tree were preserved.

All 26 Python tests passed, covering all supported privacy categories, compatibility payloads, subject and per-link context, reviewed text consent, deletion, migration and offline training. The frontend build completed with existing Vite warnings, and the restored extension passed the visual and interaction comparison. The separate Chrome smoke test passed with the live port blocked. It exercised the original Shield and manual email views through a real loopback API, clipboard and history interactions, a V2 redaction request and a synthetic overlay added through DOM mutation. Direct warm-call median/p95 timings in milliseconds were 0.069/0.079 for privacy, 5.056/5.270 for email with a link, 5.035/5.563 for URL and 0.010/0.011 for page observations. These measurements exclude HTTP, Chrome and the optional LanguageTool process.
