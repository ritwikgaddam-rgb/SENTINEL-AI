# SentinelAI model and Chrome extension handover

## November 27, 2026 · Hackathon release

The release retains its TF-IDF email classifier and local URL model. The validation-selected character model caught 59 of 88 phishing examples and flagged 71 of 87 legitimate emails in the manual benchmark. The deployed policy caught three and produced zero false alerts on that set. The web and Chrome displays now label their 0–100 values as risk indices. The report records cohort metrics, the deployment rationale, clean installation checks and the limits of browser verification. [Release report](RELEASE_REPORT.md) · [Lightweight model evaluation](docs/release-model-evaluation.json) · [Installation](INSTALL.md) · [Demonstration](DEMO_GUIDE.md)


## November 26, 2026 · Gemini architecture and threshold evaluation

**Deployment decision.** The verified Chrome build is `extension/dist`. Retain the corrected contextual release. The candidates showed different trade-offs across sources and none earned promotion. [Current measured results](docs/gemini-evaluation.json) · [Precision–recall and ROC curves](docs/gemini-curves.png)

### Reconciliation and evaluation design

The checkout was on `main` at `24feb47`. That history includes the earlier Gemini work in `a2b5405` and `24feb47`. It also held the uncommitted Codex contextual fixes and tests. The four new upgrades were documented in the local Gemini PDF and Markdown handover. Their source patch did not appear in the working tree, Git history, worktrees or the three remote branches. The exact revision of Gemini’s draft could not be verified. The handover cites the earlier six detections on the manual set, which predates the corrected policy's three. I reconstructed the documented methods in separate research modules. The shared threshold fix, credential and negation logic, URL parsing, privacy, SQLite failure behavior and standalone worker passed their existing tests. No Git merge conflict occurred.

`training/gemini_features.py` implements source weighting, shared-host and destination cues, benign-format signals, sparse-header features, masked text windows and fit-only cosine prototypes. Shared hosting suggests something to check only when the message provides action or path context. Newsletters, receipts and thread conventions are inputs to a fitted model. A reply prefix requires a visible quote before the feature records thread context. Sender authentication remains unknown where the receiver has supplied no verified result. URL destinations and redirect parameters are inspected locally as strings.

The three candidates were **Structure+**, **Regime-aware sparse LR**, and the **deconfounded multi-view stack**. The stack combines a structural score, a word-model logit, a sparse-header indicator, a semantic LR logit and a class-prototype margin. Using learned logits and adding the semantic branch are reconstruction choices. A held-out stacking partition fits the fusion model. An additional variant swaps word LR for character LR and uses the structural model with regime interactions. One further variant retains both lexical models.

The seed fixed group assignment and sampling before scoring. The candidate fit contained **2,722** rows, the meta fit **771**, and the sigmoid calibration **910**. The existing calibration partition is diverse by available source, with an archival and legacy-CSV bias. Per-source-and-label fit caps apply to the prior pool, with 626 additional screened template, ham-SMS and archive rows. Vocabulary, scaling, centroids and component weights fit on training only. Meta fitting, sigmoid calibration and cutoff selection each use disjoint rows. The enlarged cutoff pool added **181** from the spare grouped archive fold after shingle screening. Seventy-five benign messages were reserved from the original and spare pools for topical limits, leaving **782** original and **963** expanded cutoff rows. The 18 older benign guards are shown separately.

The historic manual (175), original short (93), mixed (884), authentication (15), transactional (5) and archived-email (280) cohorts are development or repeat evaluations. Two archival 280-message sets share their phishing messages. The fresh sample contains **145 unused 2025 phishing emails and 200 unused UCI benign texts**. Deterministic hashing selected unused archive rows after checking normalized body and 12-word fingerprints against every retained partition. This sample was held out from the new candidates and cutoff decisions. It shares parent archives with the previous work, and the two labels come from different sources and message channels. It cannot establish independence at the source level or typical mailbox precision. Frozen baselines were evaluated at their original cutoffs and only on cohorts supported by their original training and evaluation histories. Some prior semantic artifacts could not be scored on the mixed set because of possible fit overlap. Labels were taken from the corpus or publisher, with the source limitations described in the earlier audit. [Dataset audit](PHISHING_MODEL_REPORT.md)

### Three candidates at locked operating points

The selected research caution uses a 2.5% false-positive budget on expanded validation, and high risk uses a 1% budget. Supported categories each share that cap. Only professional/school correspondence had at least 20 benign reserve rows (55). Separate sensitivity applies each cap to all five categories, including authentication (2), security advice (2), transactional (5), and personal (11). At sizes below 20, even a 5% limit requires zero alerts. These small reserves are useful for finding defects and too small to validate a low authentication false-positive rate. The 15 inspected authentication templates remain a separate result. Both caution and high risk count as alerts. Calibration and thresholds use validation labels alone. The production policy's unknown outcomes count as misses on phishing. Research candidates provide scores for all evaluated mail.

Cells show **recall / FPR** in percent, or false positives out of the total for an all-benign set. A dash marks an unavailable comparison.

| Model | Manual | Original short | Mixed grouped | Archived email | Authentication templates | Transactional templates | Unused archive/SMS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Corrected production | 3.4 / 0.0 | 0.0 / 0.0 | 3.8 / 0.2 | 6.4 / 0.0 | 0/15 FP | 0/5 FP | 11.0 / 0.0 |
| Structure+ | 40.9 / 5.7 | 0.0 / 0.0 | 9.0 / 1.0 | 55.0 / 2.1 | 0/15 FP | 0/5 FP | 49.0 / 0.0 |
| Regime-aware sparse LR | 39.8 / 8.0 | 0.0 / 0.0 | 8.2 / 1.2 | 55.7 / 1.4 | 0/15 FP | 0/5 FP | 49.7 / 0.0 |
| Multi-view stack | 76.1 / 75.9 | 100.0 / 41.9 | 88.2 / 4.4 | 94.3 / 3.6 | 14/15 FP | 5/5 FP | 93.1 / 3.5 |
| Previous full structure LR | 51.1 / 10.3 | 5.3 / 0.0 | 14.5 / 4.6 | 47.1 / 12.1 | 0/15 FP | 0/5 FP | — |
| Full word LR | 13.6 / 9.2 | 84.2 / 1.4 | 44.4 / 0.6 | 40.0 / 0.0 | 4/15 FP | 1/5 FP | — |
| Full character LR | 12.5 / 3.4 | 78.9 / 0.0 | 41.9 / 0.0 | 40.0 / 0.0 | 5/15 FP | 1/5 FP | — |
| Curated character LR | 36.4 / 35.6 | 84.2 / 0.0 | 20.0 / 0.6 | 85.7 / 1.4 | 1/15 FP | 1/5 FP | — |
| Full three-component stack | 13.6 / 5.7 | 78.9 / 0.0 | 46.0 / 0.0 | 41.4 / 0.0 | 7/15 FP | 1/5 FP | — |
| November 25 structure LR | 51.1 / 4.6 | 5.3 / 0.0 | — | 55.0 / 1.4 | — | — | — |
| November 25 MiniLM + LR | 26.1 / 19.5 | 84.2 / 14.9 | — | 59.3 / 0.0 | — | — | — |
| November 25 BGE + LR | 30.7 / 19.5 | 100.0 / 17.6 | — | 62.9 / 0.0 | — | — | — |
| November 25 probability ensemble | 46.6 / 28.7 | 100.0 / 32.4 | — | 85.0 / 0.0 | — | — | — |
| November 25 link interaction | 55.7 / 58.6 | 100.0 / 32.4 | — | 91.4 / 0.7 | — | — | — |
| November 25 separate link regimes | 53.4 / 48.3 | 100.0 / 32.4 | — | 89.3 / 0.0 | — | — | — |
| Original fine-tuned MiniLM | 0.0 / 0.0 | 0.0 / 0.0 | — | 0.0 / 0.0 | — | — | — |
| Two-block MiniLM | 6.8 / 1.1 | 52.6 / 0.0 | 7.7 / 0.0 | 20.0 / 0.0 | 4/15 FP | 4/5 FP | — |

| Candidate | Caution cutoff | High-risk cutoff | Manual caution TP / FP / TN / FN | Manual high-risk TP / FP / TN / FN | Unused archive/SMS caution TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Structure+ | 0.676386 | 0.701807 | 36 / 5 / 82 / 52 | 28 / 3 / 84 / 60 | 71 / 0 / 200 / 74 |
| Regime-aware sparse LR | 0.580659 | 0.607576 | 35 / 7 / 80 / 53 | 25 / 6 / 81 / 63 | 72 / 0 / 200 / 73 |
| Multi-view stack | 0.684914 | 0.849370 | 67 / 66 / 21 / 21 | 56 / 56 / 31 / 32 | 135 / 7 / 193 / 10 |

At the caution cutoff the multi-view stack had 95.1% precision and 94.1% F1 on the unused archive/SMS sample. Its 95% Wilson intervals were 87.8–96.2% for recall and 1.7–7.0% for FPR. On the manual cohort it had 50.4% precision and 60.6% F1. The 14 false positives among 15 authentication templates give an observed FPR of 93.3%, with a 95% Wilson interval of 70.2–98.8%. Structure+ produced five false alerts among 87 legitimate manual emails and caught zero of the 19 phishing messages in the original short cohort.

### Threshold sensitivity and MiniLM

The multi-view stack gave the following detection counts on the expanded cutoff pool of 381 phishing and 582 legitimate messages. Each cell records TP / FP. The last row uses the original-sized pool. The evaluation results at each fixed cutoff are in the aggregate ledger.

| Validation policy | 1% FPR | 1.5% FPR | 2.5% FPR | 5% FPR |
| --- | ---: | ---: | ---: | ---: |
| Expanded, pooled FPR | 339 / 5 | 340 / 6 | 353 / 14 | 358 / 23 |
| Expanded plus zero guards | 267 / 2 | 267 / 2 | 267 / 2 | 267 / 2 |
| Expanded plus supported categories | 339 / 5 | 340 / 6 | 353 / 14 | 358 / 23 |
| Expanded plus all five categories | 90 / 1 | 90 / 1 | 90 / 1 | 90 / 1 |
| Original pool plus supported categories | 290 / 4 | 293 / 6 | 300 / 11 | 310 / 22 |

At the 2.5% budget, enforcing every category reduced false alerts on the external authentication templates from 14 to two. Manual phishing detections fell from 67 to nine, and archive/SMS detections fell from 135 to 61. Requiring zero alerts on the older guard set caught 37 manual and 109 archive/SMS phishing messages, with nine authentication false alerts.

The original fine-tuned MiniLM reproduced 49/66 phishing detections and 5/333 false positives at 0.5 on the old tuning set. At the four requested FPR limits the results were as follows. Each cell records TP / FP / guard FP.

| Old MiniLM policy | 1% FPR | 1.5% FPR | 2.5% FPR | 5% FPR |
| --- | ---: | ---: | ---: | ---: |
| Archive validation | 47 / 2 / 4 | 48 / 4 / 4 | 52 / 7 / 4 | 54 / 15 / 6 |
| Archive plus zero guards | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 |

A positive-slope sigmoid keeps the order of predictions. It can move a reporting cutoff closer to one while preserving which validation samples rank above it. The original checkpoint's Brier error was 0.041 on archive tuning and 0.234 on the benign guards. Thirteen archive scores and one benign guard score exceeded 0.999. The guard outlier and the hard guard limit explain why the cutoff suppressed detections. Threshold relaxation restores old archive recall, with the false alerts measured above. A fixed 0.5 cutoff is included for reproduction. The aggregate JSON contains PR/ROC coordinates, exact rank-based AUROC and average precision, Wilson intervals, class counts, confusion matrices and observed operating points. Curve precision depends on each cohort’s prevalence.

Multi-view model calibration varied by source. Each cell contains Brier error / 10-bin ECE. Smaller values indicate better probabilistic fit to that cohort’s reference labels.

| Cohort | N | Raw sigmoid | Global calibrated |
| --- | ---: | ---: | ---: |
| Calibration | 910 | 0.039 / 0.041 | 0.034 / 0.013 |
| Manual | 175 | 0.373 / 0.339 | 0.431 / 0.411 |
| Short | 93 | 0.278 / 0.318 | 0.321 / 0.336 |
| Authentication | 15 | 0.768 / 0.855 | 0.883 / 0.927 |
| Unused archive/SMS | 345 | 0.035 / 0.033 | 0.035 / 0.031 |

### Ablation and deployment evidence

All ablations use the same groups. Source weight tests compare unweighted fitting and modern-to-legacy benign ratios of 2, 3 and 5, with legacy benign weight 0.6 in each weighted run. The modern subset is based on known current templates or observed benign formatting. The main sigmoid is unweighted. One calibration ablation applies the documented 5:1 ratio on the separate calibration partition.

The following ablation results lock at the **1.5%** expanded-pool category operating point. Each cell shows recall / FPR in percent or the false-positive count for the benign templates. ESS is Kish effective fit sample size.

| Variant | Fit ESS | Validation | Manual | Short | Mixed | Auth | Unused archive/SMS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Multi-view stack | 2611 | 89.2 / 1.0 | 63.6 / 64.4 | 100.0 / 40.5 | 80.3 / 2.3 | 13/15 FP | 90.3 / 2.0 |
| Without benign context | 2611 | 89.2 / 1.4 | 63.6 / 65.5 | 100.0 / 40.5 | 80.5 / 2.3 | 13/15 FP | 90.3 / 2.0 |
| Previous structural features | 2611 | 89.2 / 1.4 | 63.6 / 65.5 | 100.0 / 40.5 | 80.5 / 2.3 | 13/15 FP | 90.3 / 2.0 |
| Without structural branch | 2611 | 89.2 / 1.4 | 63.6 / 65.5 | 100.0 / 40.5 | 80.5 / 2.3 | 13/15 FP | 90.3 / 2.0 |
| Without sparse flag | 2611 | 88.5 / 1.4 | 79.5 / 81.6 | 100.0 / 40.5 | 79.5 / 3.1 | 12/15 FP | 94.5 / 2.0 |
| Without prototypes | 2611 | 88.2 / 1.2 | 67.0 / 58.6 | 100.0 / 40.5 | 79.7 / 2.3 | 9/15 FP | 91.0 / 2.0 |
| Without semantic inputs | 2611 | 71.7 / 1.0 | 42.0 / 47.1 | 94.7 / 40.5 | 55.1 / 1.7 | 10/15 FP | 77.2 / 1.0 |
| Add char LR | 2611 | 90.3 / 1.2 | 68.2 / 72.4 | 100.0 / 40.5 | 83.3 / 3.3 | 12/15 FP | 90.3 / 2.0 |
| Structure + char + semantic | 2611 | 89.0 / 1.4 | 78.4 / 78.2 | 100.0 / 40.5 | 81.9 / 2.5 | 10/15 FP | 96.6 / 1.0 |
| Single-view MiniLM | 2611 | 77.7 / 1.4 | 58.0 / 51.7 | 100.0 / 40.5 | 65.5 / 1.9 | 12/15 FP | 86.9 / 2.0 |
| MiniLM two views | 2611 | 82.7 / 1.4 | 59.1 / 59.8 | 100.0 / 40.5 | 71.2 / 2.1 | 13/15 FP | 86.9 / 2.0 |
| BGE two views | 2611 | 87.1 / 1.4 | 59.1 / 60.9 | 100.0 / 41.9 | 77.5 / 2.1 | 13/15 FP | 85.5 / 2.0 |
| Add middle MiniLM view | 2611 | 91.6 / 1.2 | 71.6 / 73.6 | 100.0 / 41.9 | 83.8 / 3.9 | 14/15 FP | 92.4 / 2.5 |
| Unweighted fit | 2722 | 90.0 / 1.4 | 65.9 / 67.8 | 100.0 / 40.5 | 81.6 / 2.7 | 14/15 FP | 90.3 / 3.0 |
| 2:1 weighting | 2658 | 91.1 / 1.4 | 68.2 / 71.3 | 100.0 / 40.5 | 82.2 / 2.7 | 14/15 FP | 90.3 / 2.0 |
| 3:1 weighting | 2651 | 90.6 / 1.4 | 67.0 / 71.3 | 100.0 / 40.5 | 82.5 / 2.7 | 14/15 FP | 91.0 / 2.0 |
| Weighted sigmoid | 2611 | 89.2 / 1.0 | 63.6 / 64.4 | 100.0 / 40.5 | 80.3 / 2.3 | 13/15 FP | 90.3 / 2.0 |

For bodies over 160 words on the mixed holdout, the two-window stack gave 116/137 TP, 14/285 FP. The middle-window variant gave 110/137 TP, 12/285 FP. On the manual cohort those counts were 9/16 TP, 20/29 FP and 9/16 TP, 21/29 FP. These are slices at each model’s validation-selected cutoff. Both regimes supported separate sigmoid fitting. On the manual cohort, split calibration gave 55.7 / 50.6 recall/FPR versus 76.1 / 75.9 for the global fit. Among the main stack’s 21 missed manual phishing examples, 4 were short or lacked a sender or subject, and 0 had an attachment cue. Overlapping feature counts for misses and false alerts are in the ledger.

The two views retain the subject and opening 80 body words, followed by a separate closing 80 words and masked link labels. The encoders use at most 128 subword tokens per view. A third centered 80-word window measures the cost and benefit of recovering middle content. Even three windows can miss material outside their coverage. The comparison includes previously trained MiniLM, BGE, interaction and separate-regime ensembles and replay of the two fine-tuned checkpoints. Further transformer fine-tuning was deferred because the held-out distributions and limited modern authentication labels did not yet support a release decision.

The research stack uses 22.97 MB of MiniLM and 34.01 MB of BGE ONNX weights, plus tokenizers and 1.08 MB of fitted Python components. The measured CPU encoder times across the four views sum to **23.89 ms per message**. This excludes browser conversion and deployment costs. The research artifacts are Python-only.

### Verification and reproduction

All **81 Python tests and 10 Node tests** passed. The 14 new Python tests check feature behavior, grouping of validation inputs, threshold boundaries, calibration isolation and fit-only prototypes. Real Chrome loaded the installed extension twice in a disposable profile, with the second run offline. It passed the closed port 8000 check, synthetic Gmail scanning and compose, selective redaction and undo, four URL inputs and recovery with temporary SQLite paths deliberately unavailable. All **3,106** labelled replay evaluations matched Python's displayed verdict and risk score. Live Gmail and private inbox data were outside this run. The rebuild from the prior contextual release was used unchanged because this work touched research code only. Package checksum comparisons confirm the production numeric weights and rules are identical to that release.

The installed package occupied **2,141,114 bytes**. After Chrome restarted, model loading took **20.6 ms** and the first scan **26.8 ms**. Median warm time was **0.54 ms** across 50 short fixture scans. The sampled worker JS heap was **4.40 MB**. The worker made **0 HTTP requests** during those warm scans.

**Files added.** `training/gemini_features.py`, `training/gemini_baselines.py`, `training/gemini_thresholds.py`, `training/gemini_study.py`, `training/gemini_candidates.py` implement the experiments. `tests/test_gemini_features.py` and `tests/test_gemini_thresholds.py` provide regression tests. `training/plot_gemini_curves.py` renders the graph. The two previous evaluation JSON files link to the new ledger and retain their figures.

Use the existing archived inputs and checkpoints documented in the following reports. Run from the repository root with the backend Python environment and the local research dependency locations below. ONNX Runtime 1.32.0 and tokenizers 0.23.3 were used for the quantized encoder replays. The torch replay uses the previous PyTorch 2.11.0 and Transformers 4.57.6 environment with tokenizers 0.22.2. The two passes use separate dependency precedence. Feature matrices, checkpoints, caches and raw messages are kept local under the ignored `.runtime/` directory.

```sh
export PYTHONHASHSEED=42 OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2
export VECLIB_MAXIMUM_THREADS=2
export SENTINELAI_LEGACY_CSV="/path/to/Phishing_Email.csv"
PYTHONPATH=.runtime/handover/finetune-deps python -m training.gemini_study \
  .runtime/gemini-study/reproduce --legacy-csv "$SENTINELAI_LEGACY_CSV" --public-seeds --torch-only
PYTHONPATH=.runtime/semantic-deps:.runtime/handover/finetune-deps python -m training.gemini_study \
  .runtime/gemini-study/reproduce --legacy-csv "$SENTINELAI_LEGACY_CSV" --public-seeds
python -m training.plot_gemini_curves .runtime/gemini-study/reproduce/metrics.json docs/gemini-curves.png
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/*.test.mjs
python -m tests.browser_smoke extension/dist
python -m tests.standalone_chrome extension/dist --replay .runtime/context-study/published/replay.jsonl
```


## November 26, 2026 · Contextual accuracy review

**Use the corrected extension for the demonstration.** Load unpacked from `extension/dist`. The starting checkout was `main` at `24feb47`. The newly verified build uses the existing email and URL weights. None of the replacement classifiers met the recall and false-positive goals across sources. The earlier November 25 results below are retained as historical measurements. [Full current confusion counts, intervals, calibration and browser results](docs/context-evaluation.json)

### What caused the device-verification warning

The old rule matched **“Enter the verification code”** as a direct request to disclose a secret. A single match supplied high-severity evidence of 0.91 and confirmed the alert. On the sanitized fixture the email model returned **0.44304**, below its 0.5 phishing cutoff. The email policy computed `100 × (0.91 + (1 − 0.91) × 0.25 × 0.44304)`, or **92.0 risk / 8.0 Safe** after rounding. No subject marker, Reply-To mismatch or link was involved. The subject was “Device verification,” the sender used a reserved example domain, and the fixture had no Reply-To or destination. Both implementations applied the same mistaken rule. The original Gmail body, headers, authentication results and destinations were unavailable. The fixture reproduces the reported failure mode. The exact 7.8 display from that inbox remains unattributed.

| Same input before and after | Raw model output | Previous assessment | Corrected assessment |
|---|---:|---|---|
| Supplied code, entry on the page the recipient already opened, and security advice | 0.44304 | Suspicious, 8.0 safety index | No clear indicators, 88.9 safety index |
| Direct reply requesting a verification code | 0.69883 | Suspicious, 7.4 safety index | Suspicious, 7.4 safety index |
| Credential entry with an unspecified destination and no corroboration | Model still runs | Matched the disclosure rule | Insufficient information, no screening score |

The scanner checks who is being asked to send a secret and where it would go. It distinguishes issuing a code, security advice, entry in an already opened session, ambiguous entry and a request to return the secret. Each matched clause is considered separately. An advisory in one sentence cannot clear a later direct disclosure request. Ambiguous entry contributes zero numerical evidence. A separate material warning can still produce caution. A corroborating deceptive destination can still trigger a high-risk verdict. Matching visible and actual link domains or a matching sender domain never authenticates the sender. Each checked link records its registrable-domain relationship to the From address. Neither scanner receives a trustworthy receiver-verified authentication verdict through the current input contract, so authentication is reported as unavailable.

The scoring layer groups repeated security-event language across subject and body. Grammar findings remain available separately and add zero to email risk. The API identifies an index with `score_kind`. The existing extension details panel explains that the probability of safety is unknown. Model probabilities are the saved estimator’s outputs. An extreme value can be poorly calibrated on other sources.

A public authentication template exposed a second ambiguity during verification. “Email verification code” can name the code itself. The direct-request matcher now distinguishes that noun phrase from an instruction to email someone a credential. An archived message also used a doubled apostrophe in a negative instruction. Both scanners now recognize that export convention. Both samples helped refine the rules. Their subsequent results are regression checks.

### What the data supports

The initial pool contained 24,252 fit records. The shared partitioner excluded 3,216 normalized exact duplicates, 533 records with conflicting labels, 2,309 cross-partition template matches and six empty records. Grouping retained 18,188 records before this study’s holdouts and shingle screening. The local CSV provides explicit Safe Email and Phishing Email labels but incomplete per-message provenance. Of 12,351 final full-fit records, 9,452 came from that CSV and lacked both sender fields. Its fit rows included “enron” in 1,568 documents, “vince” in 573 and “linguistics” in 738. The modern-template samples have no authenticated headers or real recipient-specific destinations. The source-level counts, missing headers, link prevalence and document frequencies are in the aggregate file. Older Apache correspondence and Nazario’s labelled phishing submissions have known collection bias. The seven-source 162,413-row parquet mixes spam datasets and was excluded from training. The earlier email comparison using TREC-derived label-zero mail is retained as a stress test. No spam label was converted to phishing. [Dataset and original label audit](PHISHING_MODEL_REPORT.md)

**Three training conditions** used the same comparison splits and alert-selection protocol.

| Fit condition | Rows | Contents |
|---|---:|---|
| Capped | 2,096 | Up to 300 per source and label after the new screening. The prior study’s 2,355 used different splits. |
| Full | 12,351 | All eligible rows from the same fit pool. Historical and weakly sourced data make up most of the increase. |
| Curated | 2,478 | Excludes the local legacy CSV and pooled PhishFuzzer training seeds. Adds nine distinct Keycloak authentication templates, 571 UCI ham conversations and 46 screened 2020 phishing emails. Six of those 46 were short and 11 had no observed link. The SMS samples add informal language but differ from delivered email. |

New checks used publicly shipped django-allauth authentication templates (15), Solidus order/shipment/reimbursement locale texts (five), 71 screened 2021 Nazario phishing messages, and one published example per Zenodo generated template family (26 benign and 26 phishing). These are different kinds of evidence. Publisher template text represents intended content. Evaluating one representative per generated family avoids counting 1,900 variants as independent observations. The original 93-message Zenodo cohort uses the author-designated original messages. No private inbox was used. [django-allauth 65.11.2](https://github.com/pennersr/django-allauth/tree/65.11.2) · [Solidus v4.5.0](https://github.com/solidusio/solidus/tree/v4.5.0) · [Keycloak email messages](https://github.com/keycloak/keycloak/blob/26.0.0/themes/src/main/resources/theme/base/email/messages/messages_en.properties) · [Nazario archives](https://monkey.org/~jose/phishing/) · [UCI SMS corpus](https://archive.ics.uci.edu/dataset/228/sms%2Bspam%2Bcollection) · [Zenodo corpus](https://zenodo.org/records/23954793)

**Source shift explains why the earlier result was misleading.** In the earlier 280-email comparison, every positive came from the same phishing archive and every negative from TREC-derived mail. A classifier given only those two source names could perfectly separate the reference labels there. In the 175 manual emails, both labels occur under the same source. The earlier link-interaction ensemble alerted on 128/140 phishing and 1/140 legitimate emails in the first comparison. It alerted on 49/88 and 51/87 respectively in the manual set. Of the 51 false positives, 46 were among 75 link-bearing legitimate messages and five among 12 linkless legitimate messages. A link alone does not explain all the errors. Content, metadata availability and source changed together, so these data cannot isolate a single cause. The previous MiniLM/BGE embedding classifiers, probability blend, link interactions, separate link regimes and repaired Gemini stack are compared in the historical tables below.

The new 884-row grouped holdout has 365 phishing and 519 benign labels. Of those 884, 665 come from the two-label legacy collection and 70 from two-label public PhishFuzzer seeds. The remaining 149 include single-label sources. A mixed collection can still contain hidden source/label shortcuts. This holdout is disjoint from current candidate fit, stacking (771), calibration (910) and threshold selection (852). Historical model exposure to the underlying legacy sources is possible. The original five replay cohorts were previously inspected. Findings from repeated evaluation, including bug fixes, are developmental.

Numbers, email addresses and URL values were masked for the research lexical models. Text was bounded at 4,500 characters. The deployed body estimator retained its original preprocessing. Normalized body groups were assigned by deterministic group hash, and sampled interior 12-word shingles plus both edges were screened across partitions. Extra training samples were screened against all retained partitions. This can remove distinct boilerplate-heavy mail and cannot detect every edited or paraphrased campaign. The three-component stack fits on disjoint rows. Each candidate gets its own held-out sigmoid calibration. The cutoff maximizes tuning recall subject to under 5% tuning FPR and zero alerts on the 18 benign guards. The test labels never choose a cutoff. Precision and Brier scores depend on each cohort’s composition and assumed prevalence.

### Measured performance

Rates are percentages. Each cell below gives recall / false-positive rate at the locked cutoff. The authentication column counts false alerts among 15 benign templates. The linked JSON contains every method’s precision, recall, F1, FPR, confusion counts, denominators, Brier score where meaningful, and 95% Wilson intervals for recall and FPR across all 11 cohorts. A dash denotes an undefined metric.

| Method | Mixed holdout (884) | Manual (175) | Original short texts (93) | Authentication FP |
|---|---:|---:|---:|---:|
| Capped word LR | 28.8 / 0.2 | 34.1 / 25.3 | 89.5 / 39.2 | 11/15 |
| Capped character LR | 33.2 / 0.4 | 39.8 / 31.0 | 89.5 / 36.5 | 13/15 |
| Capped structure LR | 13.2 / 4.0 | 48.9 / 10.3 | 5.3 / 0.0 | 0/15 |
| Capped three-component stack | 32.1 / 0.4 | 39.8 / 33.3 | 94.7 / 40.5 | 12/15 |
| Full word LR | 44.4 / 0.6 | 13.6 / 9.2 | 84.2 / 1.4 | 4/15 |
| Full character LR | 41.9 / 0.0 | 12.5 / 3.4 | 78.9 / 0.0 | 5/15 |
| Full structure LR | 14.5 / 4.6 | 51.1 / 10.3 | 5.3 / 0.0 | 0/15 |
| Full three-component stack | 46.0 / 0.0 | 13.6 / 5.7 | 78.9 / 0.0 | 7/15 |
| Curated word LR | 21.6 / 0.6 | 40.9 / 52.9 | 89.5 / 27.0 | 10/15 |
| Curated character LR | 20.0 / 0.6 | 36.4 / 35.6 | 84.2 / 0.0 | 1/15 |
| Curated structure LR | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0/15 |
| Curated three-component stack | 10.4 / 0.2 | 5.7 / 4.6 | 78.9 / 27.0 | 9/15 |
| Previous MiniLM, original cutoff | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0/15 |
| Previous MiniLM, corrected cutoff on original validation | 0.5 / 0.0 | 2.3 / 0.0 | 31.6 / 0.0 | 2/15 |
| Previous MiniLM, mixed calibration | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0/15 |
| Previous MiniLM, compact masks | 0.8 / 0.0 | 2.3 / 0.0 | 31.6 / 0.0 | 2/15 |
| Two-block MiniLM | 7.7 / 0.0 | 6.8 / 1.1 | 52.6 / 0.0 | 4/15 |
| Deployed raw estimator at 0.5 | 91.8 / 3.5 | 79.5 / 75.9 | 89.5 / 40.5 | 13/15 |
| Corrected alert policy | 3.8 / 0.2 | 3.4 / 0.0 | 0.0 / 0.0 | 0/15 |

Increasing the cap helped the three-component stack on the mixed holdout, moving from 117/365 to 168/365 detections. On the manual benchmark the same change reduced detections from 35/88 to 12/88. The full stack also flagged seven authentic-template examples. The full structure model found 45/88 manual phishing messages but flagged 9/87 legitimate ones. The curated character classifier caught 120/140 in the prior archived-email comparison, yet flagged 31/87 legitimate manual emails. Adding curated examples and scaling up the historical corpus each changed the trade-off. Neither established generalization.

The full stack's Brier score was 0.023 on tuning, 0.036 on the mixed holdout, 0.409 on the manual set and 0.937 on the benign authentication templates. Lower is better. A low error on the same source mix as calibration did not transfer to another distribution. The deployed raw estimator had scores of 0.044 on the mixed holdout and 0.309 on the manual set. Historical training exposure makes its mixed result particularly difficult to interpret.

**Corrected deployed policy.** Both caution and danger count as alerts. Unscored phishing counts as a miss. All counts are messages within each cohort; the two 280-row comparisons share positives and must not be pooled.

| Cohort | N | TP / FP / TN / FN | Recall | Precision | FPR | F1 | Unscored |
|---|---:|---|---:|---:|---:|---:|---:|
| Prior manual development | 175 | 3 / 0 / 87 / 85 | 3.4 | 100.0 | 0.0 | 6.6 | 5 |
| Mixed grouped holdout | 884 | 14 / 1 / 518 / 351 | 3.8 | 93.3 | 0.2 | 7.4 | 37 |
| Authentication templates | 15 | 0 / 0 / 15 / 0 | — | — | 0.0 | — | 11 |
| Transaction templates | 5 | 0 / 0 / 5 / 0 | — | — | 0.0 | — | 0 |
| Paired generated families | 52 | 3 / 0 / 26 / 23 | 11.5 | 100.0 | 0.0 | 20.7 | 1 |
| 2021 phishing archive | 71 | 10 / 0 / 0 / 61 | 14.1 | 100.0 | — | 24.7 | 1 |
| Prior archive tuning | 399 | 8 / 11 / 322 / 58 | 12.1 | 42.1 | 3.3 | 18.8 | 0 |
| Prior original short mail/SMS | 93 | 0 / 0 / 74 / 19 | 0.0 | — | 0.0 | 0.0 | 11 |
| Prior archived phishing + UCI ham | 280 | 9 / 0 / 140 / 131 | 6.4 | 100.0 | 0.0 | 12.1 | 91 |
| Prior archived phishing + TREC ham | 280 | 9 / 0 / 140 / 131 | 6.4 | 100.0 | 0.0 | 12.1 | 8 |
| Current threshold-selection set | 852 | 16 / 5 / 519 / 312 | 4.9 | 76.2 | 1.0 | 9.2 | 29 |

On the manual set, 67 labelled phishing messages and 66 legitimate messages alerted under the raw classifier alone but received no final alert. Of those, 65 phishing and all 66 legitimate messages lacked a medium- or high-severity marker. Raising the influence of that raw score indiscriminately would restore many false alarms. The previous policy caught six phishing messages here. Two former credential-entry alerts now abstain, and a borderline payment marker lost the grammar-based boost. Its payment finding remains visible. The prior policy also flagged an ambiguous benign entry instruction. The tested change fixes the notification error at a measurable recall cost.

Of the 85 missed phishing messages on the manual benchmark, 82 displayed “No clear phishing indicators detected” and 3 displayed no score. Among the 351 misses on the mixed holdout, those counts were 325 and 26. Most missed phishing therefore received a neutral result. The aggregate JSON breaks down the displayed result by reference label for every cohort.

For the corrected policy, mixed-holdout recall has a 95% Wilson interval of **2.3–6.3%**, and FPR **0.0–1.1%**. Zero false alerts out of 15 authentication templates still permits a **20.4%** upper FPR bound. Eleven templates produced insufficient information. Labelled archival benchmarks cannot estimate everyday inbox precision or verify the safety of any particular email.

**Mixed-holdout slices.** Short means up to 30 whitespace-delimited words across subject and body. Missing metadata means sender or Reply-To is absent. Topic slices use overlapping English phrases as approximate categories. The security-advice slice has no benign reference examples. The separate publisher templates provide an additional check.

| Slice | N | TP / FP / TN / FN | Recall | FPR |
|---|---:|---|---:|---:|
| Short | 69 | 0 / 0 / 43 / 26 | 0.0 | 0.0 |
| Over 30 words | 815 | 14 / 1 / 475 / 325 | 4.1 | 0.2 |
| No observed link | 703 | 9 / 0 / 380 / 314 | 2.8 | 0.0 |
| At least one observed link | 181 | 5 / 1 / 138 / 37 | 11.9 | 0.7 |
| Authentication wording | 12 | 1 / 1 / 3 / 7 | 12.5 | 25.0 |
| Security-advice wording | 10 | 1 / 0 / 0 / 9 | 10.0 | — |
| Transactional wording | 18 | 1 / 0 / 8 / 9 | 10.0 | 0.0 |
| Personal wording | 35 | 1 / 0 / 24 / 10 | 9.1 | 0.0 |
| Professional/school wording | 108 | 0 / 0 / 97 / 11 | 0.0 | 0.0 |
| Missing header fields | 860 | 13 / 0 / 498 / 349 | 3.6 | 0.0 |
| Both sender and Reply-To present | 24 | 1 / 1 / 20 / 2 | 33.3 | 4.8 |

### What the transformer trial showed

Replaying the saved final-block checkpoint and its original calibrator reproduced the old cutoff of **1.0**. At a conventional 0.5 cutoff it caught 49/66 phishing messages and flagged 5/333 legitimate messages on the old tuning set. One benign guard scored 0.999976. Only one tuning positive scored higher. The previous search considered tuning scores and 1.0, and used strict greater-than. It skipped the maximum guard score as a candidate. The shared training commands now evaluate scores from the benign guards as candidate cutoffs. On the same original checkpoint, calibration and validation split, the corrected search chose 0.999976167 and recovered **1/66** positives with **0/333** validation false positives and zero guard alerts. At that locked cutoff the model caught **2/88** on the manual benchmark. The cutoff error accounted for only part of the recall failure.

The original training used one epoch, an unweighted binary loss, one trainable encoder block, a 2e-5 encoder learning rate and a 1e-3 head learning rate. Recalibrating that checkpoint on the mixed split still selected 1.0. Replacing lengthy placeholder tokens with short words preserved private-value masking and reduced the number of old tuning inputs over 128 tokens from 281/399 to 251/399. Median token length fell from 184 to 162. The compact masking control used the same checkpoint with its own calibration and cutoff. The new trial trained two upper blocks for two epochs on 1,500 sampled fit rows, with 160-token inputs, a positive loss weight of 0.979, and learning rates of 1e-5 and 3e-4. Differences in that combined trial cannot be attributed to one change. Exact token values and destinations remain masked. Long messages can still lose important text to truncation.

The two-block trial caught 28/365 mixed-holdout phishing messages and 6/88 manual phishing messages. It flagged 4/15 authentication templates. Its threshold was 0.999875. The base occupied 90,868,376 bytes and the research delta 14,210,165 bytes. Training took 49.0 seconds. Batched CPU inference took 4.35 ms/message with 1.34 GB peak process RSS during the experiment. The checkpoint stays out of the browser package.

### Installed Chrome and privacy verification

All **67 Python tests and 10 Node tests** passed. Fifteen sanitized credential cases were tested through the actual extension worker with the backend available and after Chrome restarted offline. The installed Gmail renderer showed the verification notice as 88.9% Safe in its existing index display, an unspecified entry instruction as “Score unavailable,” and the direct disclosure request as 7.4% Safe. Connected and offline Gmail views were exercised with synthetic documents. No live Gmail session or private inbox was used. The installed extension passed compose interaction, selective address redaction, undo, 21 detection, 12 false-positive-prevention and 32 address cases. The popup smoke test also exercised scan, privacy, history and URL shield interactions.

**3,106 labelled cohort evaluations** matched the local Python assessment on verdict, numeric risk and abstention, with maximum raw-probability difference 9.7e-16. Browser parity testing also found and fixed whitespace surrounding archived link destinations. The browser restarted with port 8000 closed, temporary storage unavailable and external network access blocked. The packaged URL model scored the four URL fixtures. The worker sent zero HTTP requests during 50 warm scans. The existing popup separately attempted a font stylesheet, which the test blocked. When the backend returned with deliberately unusable SQLite paths, it resumed scoring and reported history unavailable.

On the verified standard build, model loading took 12.7 ms, the first scan after restart 15.6 ms, and the median of 50 short worker scans 0.24 ms. The sampled worker heap was 4.39 MB. Python median on the labelled replay was 1.39 ms. The unpacked package contained 2,141,114 file bytes, including 1,273,740 bytes for the model/rule JSON and 238,022 bytes for the suffix list. Weights use their original precision. No conversion of a new research model was deployed.

**Changed files.** `backend/assessments.py`, `backend/scoring.py` and `backend/server.py` implement evidence and response changes. `extension/src/inference/screening.mjs`, `training/export_browser_models.py` and `extension/public/models/screening.json` implement and package the equivalent local rules. `training/context_study.py` and `training/context_transformer.py` implement the study. The shared cutoff selector in `training/email_recall_study.py` is covered by `tests/test_phishing_recall.py`. Shared cases live in `tests/fixtures/credential_context.json`; `tests/test_credential_context.py`, `tests/browser_model.test.mjs` and `tests/standalone_chrome.py` run them. This report and `docs/context-evaluation.json` contain the shareable results. The starting revision’s trained production weights, frontend files, privacy code and database implementation passed the protected-file diff. The isolated build’s generated popup, content script, CSS and logos matched the previous verified build byte for byte. No new application dependency or API key is required. The standard extension/dist directory was also rebuilt during the session. Its generated background.js, content.js, manifest.json and popup.html differ from their historical tracked copies. Its worker and numeric weights matched the staging build; the final shared rule asset was synchronized and the complete standard installation was tested separately.

### Reproducing this run

Run from the repository root with the existing backend environment. For research, use the previous study’s source archives and versioned model assets described below. Place `phishing-2020`, `phishing-2021`, `keycloak.properties`, `allauth.zip` and `solidus.zip` under `.runtime/context-study/inputs/`. The two ZIPs are GitHub codeload tag archives, and the properties file is the raw Keycloak file linked above. Input checksums are in the current JSON. Research uses local PyYAML, NumPy, SciPy, sklearn and joblib. The optional semantic run also uses the previous offline PyTorch, tokenizers and Transformers environment. Study output directories must be fresh. Raw archives, replay messages, learned vocabularies and checkpoints stay in the ignored local research directory.

```sh
export PYTHONHASHSEED=42 OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2
export PYTHONPATH=".:.runtime/handover/finetune-deps"
python -m training.context_study .runtime/context-study/reproduce --legacy-csv /path/to/Phishing_Email.csv --public-seeds
python -m training.context_study .runtime/context-study/reproduce-semantic --legacy-csv /path/to/Phishing_Email.csv --public-seeds --semantic
python -m training.export_browser_models
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/*.test.mjs
```

For the standard production build in a clean checkout, run `npm ci` and `npm run build` in `extension/`. The same final rules were also tested in an isolated staging build at `.runtime/context-study/extension/dist`. Use the tested build for the following commands. The installed acceptance test needs a free loopback port 8000 and a disposable Chrome profile, which it creates.

```sh
python -m tests.browser_smoke extension/dist
python -m tests.standalone_chrome extension/dist \
  --replay .runtime/context-study/reproduce/replay.jsonl \
  --results .runtime/context-study/reproduced-chrome.json
```

## Historical November 25 handover


**November 25, 2026 · main · starting revision 026a948**

The installed Chrome extension can scan available email and URLs after the Python server stops. It runs the saved body classifier and URL classifier inside its Manifest V3 service worker. An actual Chrome restart, a closed port 8000 and a blocked external network were part of the acceptance test. The Gmail document was a synthetic fixture. Live Gmail authentication and real inbox contents were outside the test.

**Deployment decision.** Use the packaged production models for the hackathon demonstration. Their scores reproduce the backend, including its weaknesses. The structural research classifier found 45 of 88 phishing messages on the development benchmark, compared with 6 for production. It still missed 18 of 19 phishing messages in the separate short-message set. The results do not support an accuracy claim for a typical inbox. [Aggregate measurements](docs/model-evaluation.json)

## Install the verified build

1. Open Chrome’s Extensions page, enable **Developer mode**, and choose **Load unpacked**.
2. Select `.runtime/handover/extension/dist`. In the Mac file picker, press **Command-Shift-G** to paste the path.
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
