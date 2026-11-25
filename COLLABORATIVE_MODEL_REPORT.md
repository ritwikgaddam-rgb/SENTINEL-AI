# SentinelAI model and Chrome extension handover

**November 25, 2026 · main · starting revision 026a948**

The installed Chrome extension can scan available email and URLs after the Python server stops. It runs the saved body classifier and URL classifier inside its Manifest V3 service worker. An actual Chrome restart, a closed port 8000 and a blocked external network were part of the acceptance test. The Gmail document was a synthetic fixture. Live Gmail authentication and real inbox contents were outside the test.

**Deployment decision.** Use the packaged production models for the hackathon demonstration. Their scores reproduce the backend, including its weaknesses. The structural research classifier found 45 of 88 phishing messages on the development benchmark, compared with 6 for production. It still missed 18 of 19 phishing messages in the separate short-message set. The results do not support an accuracy claim for a typical inbox. [Aggregate measurements](docs/model-evaluation.json)

## Install the verified build

1. Open Chrome’s Extensions page, enable **Developer mode**, and choose **Load unpacked**.
2. Select `/Users/ritwik/Documents/python/SENTINALAI/.runtime/handover/extension/dist`. In the Mac file picker, press **Command-Shift-G** to paste the path.
3. Open **Email Guard**, paste an email, and choose **Analyze for Phishing & Leaks**. Already-loaded Gmail messages also use the in-page scanner. Retrieving new Gmail messages still requires Gmail connectivity.
4. To use scan history, full privacy redaction or threat collection, run `./start_backend.sh` from the repository root. After an outage the worker checks again on a subsequent scan following a five-second cooldown.

No API key, Python installation, download of model weights or database is required on the extension-only machine. The build lives in a separate directory because the checkout already contains tracked generated assets and a stale popup reference. To build from the source in a clean checkout, run `npm ci` and `npm run build` in `extension/`, then load its `dist/`. The packaged model data files are under `extension/public/models/`. Regenerate them with `python -m training.export_browser_models` in the backend environment only when the source model artifacts change.

## What the teammate implemented

| Revision | Observed changes |
|---|---|
| `3378ab0` | Added the local database path to the ignore file. The two later research commits contain no database reliability fix. |
| `a2b5405` | Added structural link and sender features, delivery-provider handling, error slicing, threshold selection, a calibrated lexical stacking class and structural tests in `training/email_recall_study.py` and `tests/test_phishing_recall.py`. |
| `026a948` | Extended those two files with domain and linkless features, word/character TF-IDF reduced by SVD, a two-input stacker and tests. Updated generated background and content scripts, manifest and popup HTML. The referenced popup JS asset was absent from this checkout. |

The starting working tree was clean. Neither research commit changed the source extension, backend scoring, production joblib files or dependency declarations. The production training CLI still evaluated its previous lexical candidates. It did not invoke either new stacking class. The repository and local experiment directories contained source and prior Codex checkpoints, but no saved Gemini stacker, pretrained language encoder, exact run arguments, split manifest or prediction file substantiating the reported 31.8% recall. Work done elsewhere cannot be inferred from Git.

The original stacker used row-stratified folds, calibrated on base-model training predictions inside each fold and trained intermediate meta-models on those same in-sample predictions. The final meta-model also reused calibration labels. Fold and final estimators could differ. The included four-row example supplied only phishing to fit and only legitimate examples to calibration. The baseline suite reproduced a scikit-learn failure. The corrected stack uses template-group-held-out base predictions for meta fitting and separate grouped validation data for calibration and cuts. Tests check the original degenerate case and run a real mixed-label fit.

## Reproduction of previously reported results

The 175-message PhishFuzzer set contains 88 phishing and 87 legitimate examples. It has been studied repeatedly. Every figure in this section is a **development** result. Both models and the screening policy received the available sender, subject and link information as applicable.

| Method | TP / FP / TN / FN | Recall | FPR | Precision | F1 |
|---|---|---:|---:|---:|---:|
| Original body classifier alone at 0.5 | 70 / 66 / 21 / 18 | 79.5% | 75.9% | 51.5% | 62.5% |
| Current production alert policy | 6 / 1 / 86 / 82 | 6.8% | 1.1% | 85.7% | 12.6% |
| Previously selected Codex SVM plus production evidence | 23 / 8 / 79 / 65 | 26.1% | 9.2% | 74.2% | 38.7% |
| Gemini result reported in the request | Counts unavailable | 31.8% | 3.4% | 90.3% | 47.1% |
| Original Gemini stacking code rerun | 62 / 55 / 32 / 26 | 70.5% | 63.2% | 53.0% | 60.5% |

The first three rows reproduced. For the last row, the replay used the unmodified class from `a2b5405`, its default meta penalty, word TF-IDF and balanced linear SVM, the prior legacy-source fit partition, and calibration groups from the documented seed-27 split. Its locked cutoff was 0.79622. Combining it with the existing alert policy gave the same confusion counts. This is one documented reconstruction. Establishing the source of the previously reported numbers requires the original artifact or run manifest.

## Data and evaluation

- **Training.** The source and label cap selected at most 300 per available combination. After screening, 2,355 messages remained from Apache ham, 2019/2022/2023 Nazario phishing, non-manual PhishFuzzer seeds, the local labelled phishing CSV and 31 existing authored benign examples. No additional synthetic messages were created. The legacy file’s per-message provenance is incomplete. [Previous dataset audit](PHISHING_MODEL_REPORT.md)
- **Validation.** Grouped folds from the distinct 2024 Nazario archive and Apache `easy_ham_2` supplied 303 rows for stacking, 300 for sigmoid calibration and 399 for choosing cutoffs. One spare fold was unused. Eighteen separate benign messages constrained the cutoff. The criterion maximized validation recall under a 2.5% validation false-positive ceiling and zero guard alerts. This constraint describes this validation sample only.
- **Leakage controls.** The existing normalized exact/body-edge grouping runs before partitioning. Additional comparisons used 12-word interior shingles sampled with a fixed hash seed. They removed 35 fit, 161 stack, 133 calibration and 13 tuning rows. Each new holdout was screened against previously retained rows and the raw legacy CSV, including within-source duplicates. Shared long boilerplate can exclude distinct messages. Edited campaigns and undisclosed source overlap remain possible.
- **Development.** The two previously inspected sets are the 175 manual emails and 93 original Zenodo email/SMS records. The latter contains 19 phishing and 74 legitimate texts with little header evidence. Generated Zenodo variants and ordinary spam were excluded. [PhishFuzzer](https://github.com/DataPhish/PhishFuzzer) · [Zenodo validation data](https://zenodo.org/records/23954793)
- **New evaluation.** Both 280-record cohorts use the same 140 later Nazario phishing examples. One pairs them with 140 UCI ham texts. The other pairs them with 140 TREC-07-derived label-0 emails from the local parquet. The 2002 Apache ham archive contributed no new eligible examples after filtering. TREC-derived labels are a weaker reference than inspecting the original per-message judgments. The two holdouts share positives, use different sources for the two classes, and have an artificial 50% prevalence. They measure transfer to these collections. Production precision depends on the inbox’s phishing prevalence. [Nazario archive](https://monkey.org/~jose/phishing/) · [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms%2Bspam%2Bcollection) · [NIST TREC overview](https://trec.nist.gov/pubs/trec16/papers/SPAM.OVERVIEW16.pdf) · [Apache ham](https://spamassassin.apache.org/old/publiccorpus/)
- **Input handling.** Research text uses the existing quote, email, link and numeric masking before both training and prediction. This transformation cannot anonymize all personal information. The source material and candidate vocabularies stayed local. The production TF-IDF export retains its original body preprocessing. Changing it would change its predictions. Subjects, sender and Reply-To domains, and link text/destinations contribute separate evidence.

## Research architectures

The component comparison includes calibrated word LR, character LR and structural LR, two frozen pretrained encoders with LR heads, three ensembles and the repaired SVD stack. Structural inputs cover sender/reply/display inconsistencies, action links, domain structure, link density and linkless callback, transfer and attachment context. The extraction now includes body links even when an archive provides no separate anchors. Missing headers and attachment contents are never reconstructed. Delivery-provider membership cannot suppress an explicit destination mismatch. A payment word, a public email provider, an internationalized domain or a missing link is insufficient on its own for a production phishing verdict.

The pretrained encoders were **all-MiniLM-L6-v2** with attention-masked mean pooling and **bge-small-en-v1.5** with CLS pooling. Both yield normalized 384-dimensional embeddings. Local ONNX Runtime ran int8 weights with a 128-token limit. The ensemble combines the word, character, structural and both encoder probabilities. One variant adds interactions with link presence. Another trains separate small meta-models for messages with and without links. The supplied SVD pipeline remains a lexical baseline. [MiniLM weights and tokenizer](https://huggingface.co/Xenova/all-MiniLM-L6-v2) · [BGE weights and tokenizer](https://huggingface.co/Xenova/bge-small-en-v1.5)

A batch experiment exposed a reproducibility issue. Dynamic int8 inference classified one shared positive differently when the surrounding batch changed. The final encoder comparison processes one message at a time during both fitting and evaluation. The initial batch runs are retained locally. Threshold selection used validation labels. The batch-size change addressed dependence on unrelated messages. The repeat evaluations mean subsequent tuning on these cohorts would require another untouched test.

The bounded fine-tuning trial updated the final MiniLM transformer block and a binary head for one epoch. The other blocks were frozen. The calibration and tuning data stayed separate. The validation routine selected a cutoff of 1.0, giving zero alerts. The base weights used 90.9 MB and the saved head and final block used 7.1 MB. The trial took 25.8 seconds of fitting and 3.43 ms per message for batched inference, with 1.79 GB peak process RSS including data preparation. It provides no justification for shipping or scaling up the transformer. [Base checkpoint](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)

## Results at validation-selected cutoffs

Rates are percentages. Counts follow the order shown in the header. The raw body model and the final alert policy answer different questions. Each research classifier issues a binary decision at its locked cutoff. For the policy, both caution and danger count as alerts, and missed phishing includes abstentions. An em dash means no positive predictions.

### Development benchmark · 175

| Method | TP / FP / TN / FN | Recall | FPR | Precision | F1 |
|---|---|---:|---:|---:|---:|
| Packaged raw body classifier | 70 / 66 / 21 / 18 | 79.5 | 75.9 | 51.5 | 62.5 |
| Packaged production policy | 6 / 1 / 86 / 82 | 6.8 | 1.1 | 85.7 | 12.6 |
| Word LR | 34 / 29 / 58 / 54 | 38.6 | 33.3 | 54.0 | 45.0 |
| Character LR | 44 / 35 / 52 / 44 | 50.0 | 40.2 | 55.7 | 52.7 |
| Structure LR | 45 / 4 / 83 / 43 | 51.1 | 4.6 | 91.8 | 65.7 |
| MiniLM + LR | 23 / 17 / 70 / 65 | 26.1 | 19.5 | 57.5 | 35.9 |
| BGE + LR | 27 / 17 / 70 / 61 | 30.7 | 19.5 | 61.4 | 40.9 |
| Combined probabilities | 41 / 25 / 62 / 47 | 46.6 | 28.7 | 62.1 | 53.2 |
| Link interactions | 49 / 51 / 36 / 39 | 55.7 | 58.6 | 49.0 | 52.1 |
| Separate link regimes | 47 / 42 / 45 / 41 | 53.4 | 48.3 | 52.8 | 53.1 |
| Repaired Gemini SVD stack | 52 / 39 / 48 / 36 | 59.1 | 44.8 | 57.1 | 58.1 |
| Fine-tuned MiniLM | 0 / 0 / 87 / 88 | 0.0 | 0.0 | — | 0.0 |

### New email cohort · 280

| Method | TP / FP / TN / FN | Recall | FPR | Precision | F1 |
|---|---|---:|---:|---:|---:|
| Packaged raw body classifier | 86 / 10 / 130 / 54 | 61.4 | 7.1 | 89.6 | 72.9 |
| Packaged production policy | 13 / 0 / 140 / 127 | 9.3 | 0.0 | 100.0 | 17.0 |
| Word LR | 110 / 0 / 140 / 30 | 78.6 | 0.0 | 100.0 | 88.0 |
| Character LR | 122 / 0 / 140 / 18 | 87.1 | 0.0 | 100.0 | 93.1 |
| Structure LR | 77 / 2 / 138 / 63 | 55.0 | 1.4 | 97.5 | 70.3 |
| MiniLM + LR | 83 / 0 / 140 / 57 | 59.3 | 0.0 | 100.0 | 74.4 |
| BGE + LR | 88 / 0 / 140 / 52 | 62.9 | 0.0 | 100.0 | 77.2 |
| Combined probabilities | 119 / 0 / 140 / 21 | 85.0 | 0.0 | 100.0 | 91.9 |
| Link interactions | 128 / 1 / 139 / 12 | 91.4 | 0.7 | 99.2 | 95.2 |
| Separate link regimes | 125 / 0 / 140 / 15 | 89.3 | 0.0 | 100.0 | 94.3 |
| Repaired Gemini SVD stack | 114 / 0 / 140 / 26 | 81.4 | 0.0 | 100.0 | 89.8 |
| Fine-tuned MiniLM | 0 / 0 / 140 / 140 | 0.0 | 0.0 | — | 0.0 |

The validation-selected link-interaction ensemble caught 128/140 phishing emails with one false alert among 140 legitimate emails in the new email cohort. On the development set it flagged 51/87 legitimate messages. The 90% recall milestone therefore occurred in a source-separated cohort with pronounced source/label correlation. The development set did not meet the 70% or 90% milestones at the requested false-positive rate.

The structural classifier reached 51.1% development recall (95% Wilson interval 40.9–61.3%) and 4.6% FPR (1.8–11.2%). On new email it reached 55.0% recall (46.7–63.0%) and 1.4% FPR (0.4–5.1%). These intervals assume independent records and can be optimistic for related campaigns. On development messages with links it produced 33 TP, 2 FP, 73 TN and 33 FN. Without links the counts were 12 TP, 2 FP, 10 TN and 10 FN. The small linkless legitimate sample makes its false-alarm estimate particularly uncertain.

Structural LR is the strongest candidate under the **observed development** false-positive budget. That finding came from comparing measured results after validation selection. It needs another independently sampled, source-balanced evaluation before promotion. Modern benign transactional email, personal conversations and real phishing with sparse sender or link metadata deserve separate cohorts. Include paired benign billing, support, delivery-tracking and attachment messages before fine-tuning further.

The companion JSON records confusion matrices, precision, recall, F1, FPR, FNR, Brier score, ten-bin calibration error, thresholds, and abstentions where applicable. It includes both new cohorts, the short set, linkless and link-bearing development slices, and archived Codex measurements. Calibration columns describe model probabilities. The final evidence-weighted safety index has no probability calibration. [Measurements](docs/model-evaluation.json) · [Earlier candidate details](PHISHING_MODEL_REPORT.md)

## Standalone verification

| Installed policy | Records | TP / FP / TN / FN | Recall | FPR | Abstentions |
|---|---:|---|---:|---:|---:|
| Validation | 399 | 8 / 11 / 322 / 58 | 12.1% | 3.3% | 0 |
| Development | 175 | 6 / 1 / 86 / 82 | 6.8% | 1.1% | 1 |
| Previously examined short texts | 93 | 0 / 0 / 74 / 19 | 0.0% | 0.0% | 11 |
| Later phishing + UCI ham | 280 | 13 / 0 / 140 / 127 | 9.3% | 0.0% | 87 |
| Later phishing + derived email ham | 280 | 13 / 0 / 140 / 127 | 9.3% | 0.0% | 4 |

All **1,227 cohort evaluations** matched Python on the final verdict and numerical risk score, including missing scores. The two new cohorts share 140 positives. Maximum absolute difference in raw phishing probability was 5.0 × 10⁻¹⁶. The body model uses float64 and no quantization. Raw observations and final assessments can legitimately disagree. HTML-only Gmail ingestion, nonstandard address syntax, browser URL canonicalization, Unicode domains and optional server-side LanguageTool can introduce differences beyond this replay.

The QA driver launched a real backend with temporary storage, scanned a message through the installed worker, exercised Gmail compose, terminated the backend, verified connection refusal and checked that lsof found no listener on port 8000. It exercised a benign school message, a direct credential request, a multi-link message and a greeting through the actual Gmail content script. The visible bars showed 93.6%, 7.4% and 91.8% safety indices for the first three. The greeting showed “Score unavailable.” The existing popup also displayed the offline verdict and score.

A second Chrome process loaded the unpacked extension while the backend was still stopped. Chrome retrieved both model resources from its own extension origin. Network inspection found a worker loopback health probe and zero HTTP(S) requests during the 50 warm scans. The popup independently attempted its existing Google Fonts stylesheet and loopback health request. External network access was blocked. The inference worker made no external requests, and no email text or links were sent during the measured warm scans. Restarting the backend with both database paths deliberately unusable restored connected model scoring. All test-owned services were then stopped.

## Runtime and resource use

On this Mac the packaged model took **14.6 ms** to load and validate. First scan after restart took **17.4 ms** including the probe and extension messaging. Warm median was **0.25 ms** over 50 short fixture scans. Worker JS heap sampled after scans was **3.78 MB**. CPU time across Chrome processes was **25.0 ms** for those 50 scans. Python's median full assessment across the labelled replay was **1.47 ms**. These timings cover different input distributions and exclude Gmail retrieval and network latency.

The model JSON is 1,272,723 bytes. The bundled public suffix snapshot is 238,022 bytes. The complete unpacked distribution contains 2,140,768 file bytes, or 918,559 bytes in a level-6 ZIP measured in memory. No extra JavaScript ML runtime is required. Package checks run once per worker lifetime. Chrome can evict idle workers and reload the models on demand.

| Research candidate | Files needed (MB) | Python ms per message | Peak process RSS (MB) |
|---|---:|---:|---:|
| Word LR | 0.467 | 0.37 | 228 |
| Character LR | 0.572 | 0.69 | 233 |
| Structure LR | 0.003 | 0.69 | 211 |
| MiniLM + LR | 23.689 | 3.86 | 298 |
| BGE + LR | 34.730 | 7.21 | 344 |
| Combined probabilities | 59.458 | 12.67 | 348 |
| Link interactions | 59.458 | 12.62 | 366 |
| Separate link regimes | 59.459 | 13.87 | 357 |
| Repaired Gemini SVD stack | 15.603 | 2.07 | 286 |

Each research row measures one fresh Python process over 175 development messages. Model loading, feature extraction and calibration are included in the timed operation after shared input preparation. RSS includes Python and imported libraries. Ensemble sizes include base models and tokenizers. The tuned FP32 model’s training-process peak and inference time are reported with its trial above. ONNX encoders have a browser-compatible file format. Only the production JS pipeline was packaged and benchmarked in Chrome.

## Browser architecture and persistence

The popup manual scanner, Gmail inbox scanner, in-page Gmail scanner and URL shield use the MV3 background service worker for scans. A bounded loopback health probe runs on demand. A shared promise combines concurrent checks, with a 900 ms probe timeout, a six-second bound on the connected scan request, a five-second failure cooldown and a 30-second healthy cache. Losing the server during a request invokes the local classifier. The worker accepts scan requests only from the extension’s own popup and permitted top-level Gmail content script. It bounds payloads, omits attachments, strips unnecessary response data for Gmail and refuses remote backend origins and redirects.

The exporter reads the existing sklearn artifacts and emits the fitted intercept, 20,000 indexed unigram/bigram IDF and coefficient pairs, URL tree nodes with their column order, and shared regex/brand definitions. Term keys are deterministic hashes with a collision check over the saved vocabulary. Vocabulary hashes can still be guessed. The browser performs Unicode word tokenization, term counting, L2 normalization, logistic scoring and positive-class mapping for email. URL scoring traverses the numeric trees. Subject, sender, Reply-To when available, visible and actual links, local writing and contextual evidence feed the bounded policy. Links are inspected as strings. The established display scores summarize the evidence and cannot establish that a message is safe.

SQLite errors previously could discard a computed verdict or prevent backend startup. The storage boundary now handles filesystem and SQLite exceptions separately for history and opt-in threat collection. Returned persistence fields distinguish a successful write, skipped collection and unavailable storage. Health inspects the history database. Privacy audit failure preserves the computed redaction. Inference failures retain their own error state. There are no retries or queues for private messages. The database schema and paths are preserved.

Full privacy detection, history persistence, threat collection and optional writing-service analysis still require the local backend. The worker returns a clear availability marker and offers no substitute redaction or raw “redacted” copy. Fetching Gmail content through OAuth is separate from inference. Live reputation is unavailable in standalone mode. A missing or unreadable model yields an explicit unavailable result with no fabricated score.

## Tests and reproducibility

- **65 Python tests passed**, including HTTP origin restrictions, request validation, scoring, temporary SQLite history, threat collection, privacy, Aadhaar/phone checks, address spans and optional storage failures.
- **8 Node tests passed**, including packaged model loading, the original greeting probability, abstention, sender parsing, multiple destinations, model corruption and Gmail request protections.
- **Installed Chrome** passed the 21 positive privacy cases, 12 numerical false-positive cases and 32 address cases. The existing compose suite also verified category selection, bulk consent, rich text, position-based redaction and undo. The existing browser preview test passed its Shield, Email, Privacy, History and page fixtures.
- Source and build checks covered the official logos, compiled CSS, compose script, native model artifacts and generated manifest. Only the offline privacy-status sentence in the existing email result component changed. The original checkout and trained artifacts remain available for rollback.

From the repository root, with the existing backend environment activated, the regression commands are:

```sh
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/*.test.mjs
python -m tests.browser_smoke .runtime/handover/extension/dist
python -m tests.standalone_chrome .runtime/handover/extension/dist \
  --replay .runtime/handover/single-mail/replay.jsonl \
  --results .runtime/handover/recheck-chrome.json
```

The installed Chrome test uses a disposable profile, requires the DevTools unpacked-extension command and needs port 8000 free. It only shuts down the backend process it starts. Omitting `--replay` runs the installed acceptance tests without any research corpus.

For research, use the same local input archives as the previous study. The new resource directory contains `mini/` and `bge/`, each holding its tokenizer JSON and the corresponding quantized ONNX model saved as `model.onnx`. The `fresh/` directory holds the publisher archives for 2025 phishing, 2002 Apache ham and the UCI SMS ZIP. See the hashes and split counts in the aggregate JSON. Use a new output directory for every run. The extra Python dependencies are research-only. The measured configurations used ONNX Runtime 1.32.0, tokenizers 0.23.3 and PyArrow for the local parquet. The separate fine-tuning environment used PyTorch 2.11.0, Transformers 4.57.6 and tokenizers 0.22.2.

```sh
PYTHONHASHSEED=42 OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
python -m training.handover_study .runtime/handover .runtime/handover/recheck-study \
  --legacy-csv "$HOME/Downloads/Phishing_Email.csv" --public-seeds \
  --parquet "$HOME/Downloads/train.parquet"
```

For the bounded transformer run, add `--fine-tune`, choose another output directory and use the official MiniLM `config.json` and `model.safetensors` under `mini-train/`. The original, reconstructed Gemini class and research invocation used here are in `.runtime/handover/gemini_original.py` and `.runtime/handover/replicate.py`. The original code can also be recovered from Git with `git show a2b5405:training/email_recall_study.py`. All new research checkpoints are separate from production in `.runtime/handover/single-mail/` and `.runtime/handover/fine-final/`. These local directories and public input archives are outside version control. The aggregate JSON and this report can be shared without the email bodies.

## Changed files

| Files | Purpose |
|---|---|
| `backend/server.py` | Independent persistence failure handling, startup and health reporting. |
| `extension/manifest.json`, `extension/src/background/background.js` | Register the module service worker and route validated scan messages. |
| `extension/src/inference/screening.mjs`, `extension/src/inference/worker.mjs` | Packaged inference, feature extraction, scoring, connection recovery and worker lifecycle. |
| `extension/public/models/screening.json`, `extension/public/models/public_suffix_list.dat` | Fitted parameters and the licensed public suffix snapshot, available on installation. |
| `extension/src/content/content.js`, `extension/src/popup/gmailApi.js`, `extension/src/popup/localApi.js` | Use worker scans from the existing controls, including short messages, sender details and Gmail MIME link labels. |
| `extension/src/popup/components/EmailScannerTab.jsx` | Display an unavailable privacy check accurately in the existing text slot. |
| `training/email_recall_study.py`, `training/handover_study.py`, `training/tune_minilm.py`, `training/export_browser_models.py` | Repair the teammate’s stacking method, compare candidates, run one local fine-tuning trial and reproduce the browser export. |
| `tests/test_phishing_recall.py`, `tests/test_optional_storage.py`, `tests/browser_model.test.mjs`, `tests/standalone_chrome.py` | Training, database, model, request-boundary, compose control and installed browser regressions. |
| `COLLABORATIVE_MODEL_REPORT.md`, `docs/model-evaluation.json` | Findings, measured performance, artifact inventory and reproduction instructions. |
