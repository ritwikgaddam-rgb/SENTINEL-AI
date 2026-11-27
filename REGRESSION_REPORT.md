# Scoring and privacy regression verification

## Root causes

The backend returned null risk and safety scores on V2 and deliberately substituted a string dash in the legacy response. The restored React and Gmail views appended a percent sign to that string. The legacy adapter also translated an uncertain result into an amber phishing warning. The URL runtime loaded the structural candidate only to report its binary observation. It read no probabilities for scoring, and the email classifier was absent from the runtime. Model files themselves loaded successfully.

The Privacy tab and Gmail compose both bypassed the Python detector. Their earlier JavaScript expressions matched digit lengths and prefixes. The compose script recognized Aadhaar and phone numbers only, while the Privacy tab also recognized email addresses. Email Guard's earlier copy control replaced those same three categories and the adapter suppressed its button when another category was present. The current bundle removes those bypasses. The old tracked bundle remains the visual reference.

## Scoring behavior

The shipped email TF-IDF and logistic regression artifact loads with class 1 as phishing and receives the body using its saved preprocessing. The evaluated URL gradient-boosted artifact uses class 1 as phishing and its saved structural feature order. The legacy random forest also loads, uses class 0 as phishing and remains available for comparison. Earlier tests found 99.87% false positives for that forest on the reference domain holdout. No model was retrained or overwritten.

The computed risk index combines independent evidence with bounded contributions from the learned signals. Multiple markers in one category contribute once at their strongest severity. URL scores use the evaluated model's ordinary binary classification boundary for a caution. A high-risk alert needs strong or corroborated evidence. The email model can move the index and affect the alert level alongside independent evidence. Grammar adds limited support. Short messages with too little context and failed predictions explicitly return an unscored state. Privacy findings never affect phishing risk. Scores are screening indices. Confidence remains null because the combined score is uncalibrated.

| Input | Old legacy API | Current risk / safety | Current assessment |
|---|---|---|---|
| Amazon India search URL | null / dash | 32.5 / 67.5 | No clear phishing indicators detected |
| Flipkart | null / dash | 34.9 / 65.1 | No clear phishing indicators detected |
| YouTube search | null / dash | 16.8 / 83.2 | No clear phishing indicators detected |
| Synthetic hostname deception | null / dash | 95.1 / 4.9 | Suspicious |
| Hello | null / dash, amber | null / null, neutral display | Insufficient information |
| Ordinary school meeting email | null / dash | 2.9 / 97.1 | No clear phishing indicators detected |
| Verification-code request | null / dash | 92.6 / 7.4 | Suspicious |

V2 exposes the separate model prediction and probability. Legacy routes keep their existing response fields and return numbers when available. The old score suffix and fabricated offline defaults have been removed from the renderers where no score exists. Existing scan history stays intact. New history can display recorded screening scores without reusing obsolete confidence numbers.

### Reference cohorts

The 175 English PhishFuzzer examples include 87 legitimate and 88 phishing messages. The new policy issued one false alert, two high-risk phishing alerts and three phishing cautions. Among phishing examples, 81 had no clear indicators and two were unscored. Alert recall was 5.68% when both alert levels count. This remains a weak email detector on the benchmark. The saved email artifact performed poorly on false positives and prior text candidates did not improve that tradeoff sufficiently. The local email screen warrants continued evaluation.

The reference URL holdout has 17,473 benign and 19,158 phishing addresses from unseen domain groups. Counting cautions and high-risk alerts together gave 2,126 false alerts (12.17%) and 16,837 detected phishing URLs (87.89% recall). Six benign and 298 phishing URLs received high-risk alerts. This reuses the existing reference benchmark and is not a new post-change external validation. Detailed counts are in the private research archive under `research/scoring-privacy-verification/scoring-evaluation.json`. [Archive location](RELEASE_REPORT.md#archived-research) · [Earlier model and dataset audit](V2_REPORT.md)

## Redaction and compose

The common validator supports email addresses, Indian and international phones, Aadhaar, residential and mailing addresses, Indian PIN and international postal or ZIP codes, US SSNs, bank accounts, IFSC, IBAN, credit and debit cards, PAN, passports, UPI IDs, explicit passwords, API keys and authentication tokens. These map to 16 API categories. Individual fixtures exercise each category. The installed extension detected all 20 expected automatic matches in the mixed draft and flagged two additional review-only matches. Both ordinary order and tracking identifiers remained intact even after Redact all. Additional fixtures cover Verhoeff and Luhn failures, ambiguous numbers, multi-line US addresses, Unicode offsets and overlapping spans. The fixtures do not establish a population-level privacy error rate.

Valid labelled Aadhaar requires a valid starting digit, identifier boundaries and the Verhoeff checksum. A labelled invalid format or checksum is review-only. Unlabelled plausible numbers require review, and the tested labelled order, invoice and tracking numbers stayed intact. The phone validator checks numbering-plan rules and context. The controlled draft recognized the Indian and US fixtures, left the unlabelled phone-like number unchecked and excluded the labelled order number.

The collapsed pill keeps the original icon, badge, dimensions, position and hover styles. The expanded drawer reuses the existing audit card, buttons, theme colors and animation. It groups masked findings, distinguishes review-only values and provides category and occurrence selection, select all, deselect all, redact selected, redact all, collapse and undo. It has separate state per editor. Draft changes invalidate old spans, quotes and signatures are excluded by default, and selected edits preserve unrelated DOM nodes and hyperlinks. Undo applies only if the edited nodes still match. Gmail draft requests go from the extension service worker to loopback. Temporary audit tests checked counts and empty original samples.

## Verification and affected frontend files

All 31 Python tests passed. The installed unpacked extension was tested in disposable Chrome against a temporary backend and a simulated Gmail page. It displayed actual numeric URL and email scores, used the expanded Privacy tab backend preview, and showed all 16 categories in one compose draft. The test covered category and occurrence selection, deselect all, redact all, undo, stale edits, isolated drafts, formatting and quoted text. The standalone browser preview test also passed. The collapsed pill had matching geometry and identical cropped pixels in the before and after screenshots. Live Gmail, live OAuth and additional Gmail editor variants remain manual checks.

| File | Change |
|---|---|
| extension/src/popup/App.jsx | Reports an unavailable scan in the existing card when the URL is unsupported or the API fails. |
| extension/src/popup/components/ShieldStatus.jsx | Renders numeric scores or a neutral unavailable state in the existing card. |
| extension/src/popup/components/EmailScannerTab.jsx | Removes local guesswork, renders real scores and copies the full backend redaction. |
| extension/src/popup/components/PrivacyGuardTab.jsx | Connects the existing counters, preview and copy control to Python validation. |
| extension/src/popup/components/HistoryModal.jsx | Displays the stored screening score when present. |
| extension/src/popup/gmailApi.js | Passes subject, Reply-To and labels already available from Gmail. |
| extension/src/content/content.js | Connects the existing Gmail overlays and compose trigger to the updated responses. |
| extension/src/content/composePrivacy.js | Implements the selectable, position-based compose redaction and in-memory undo. |
| extension/src/content/gmailOverlay.css | Adds styles scoped to the expanded compose state. |
| extension/src/background/background.js | Bridges compose privacy calls to loopback and removes raw selection logging. |

The remaining modified files are backend/scoring.py, backend/server.py, backend/url_advisory.py, backend/database.py, privacy_detector.py, tests/test_v2.py, tests/browser_smoke.py, README.md and this report. The source popup HTML and styling are unchanged. The bundled popup HTML differs only in the rebuilt JavaScript asset name, and the bundled popup CSS matches byte for byte.

The Shield and compose screenshots are in the private local research archive under `research/scoring-privacy-verification`. [Archive inventory and location](RELEASE_REPORT.md#archived-research)

Build and load `extension/dist` with the [setup instructions](INSTALL.md) to repeat the browser checks. A previously running backend continues to serve its loaded code until restarted. The validation ran in temporary databases, leaving the existing history and running process intact.
