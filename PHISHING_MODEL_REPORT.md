# SentinelAI email phishing recall study

## Decision

**Retain the original production model and the existing alert policy.** The two validation-selected replacements improved recall on their development datasets, but both exceeded the 5% false-positive target on the independent 175-message cohort. The best low-false-positive alternative caught 10 of 88 phishing messages, compared with 6 under the current policy using available link metadata. It still missed 78 phishing messages. It remains an offline research candidate. This study did not establish a policy that reliably met the desired recall, precision and false-positive targets across sources.

## Why the audit reported 5.7% recall

I recovered the exact PhishFuzzer release used in the final audit and verified its SHA-256 against the archived run. Replaying the same 175 English Manual messages with body, subject and sender reproduced the result. The raw and policy confusion matrices below use phishing as the positive class.

| Stage on the original replay | Accuracy | Precision | Recall | F1 | False-positive rate | False-negative rate | TN / FP / FN / TP | Coverage |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| Raw classifier at 0.50 | 52.0% | 51.5% | 79.5% | 62.5% | 75.9% | 20.5% | 21 / 66 / 18 / 70 | 100% |
| Existing alert policy, caution or danger | 52.0% | 83.3% | 5.7% | 10.6% | 1.1% | 94.3% | 86 / 1 / 83 / 5 | 98.9% |

The raw classifier flagged 70 of 88 phishing messages. The alert policy suppressed 66 of those correct raw flags and raised one alert that the raw classifier missed. Of the 83 missed phishing messages, 81 received no alert and two were unscored. Heavy abstention therefore does not explain the low recall. Both artifacts loaded, and the email model returned valid probabilities for all 175 messages. The deployed TF–IDF plus logistic regression classifier uses class 1 for phishing with the saved 20,000-feature word unigram/bigram vectorizer. It receives body text using the same vectorizer and class order as fit. No inversion, missing artifact or failed inference was found.

The email policy gives the model at most 25 points on the 100-point risk index before independent evidence contributes. An email without a qualifying evidence category cannot reach the model-and-evidence caution route at 40 points. Existing high-confidence evidence can still raise an alert directly. The rule sharply reduces false alarms from a raw model whose Brier score was 0.309, 10-bin expected calibration error was 0.214 and average precision was 0.526 on the same cohort. Lowering the display cutoff alone would expose many of those false alarms.

All 175 messages had subjects and sender fields in the original replay, and 31 yielded links from the body. Reply-To was unavailable from that source. The new comparison additionally supplies the publisher's URL fields where present, without inventing visible link labels. That added one true positive in the current policy, taking recall to **6.8%** on the same 175 bodies. Those two baselines are reported separately. The original 5.7% and the 6.8% rerun use the same alert policy with different supplied link metadata.

## Sources, label quality and leakage

| Corpus | Audit and role |
|---|---|
| Local `Phishing_Email.csv` | 18,650 rows, 11,322 labelled Safe Email and 7,328 labelled Phishing Email. There were 19 blank/missing bodies, 1,095 exact duplicate rows after dropping blanks and one exact body with conflicting labels. The original script kept the first duplicate. That leaves 10,979 legitimate and 6,557 phishing rows. Only 141 legitimate bodies had 1–7 normalized words. This file has body and label but no per-message source or campaign field. Its layout matches the original training script, although exact training-file identity is unproven. It was used only in fit A. |
| Local `train.parquet` | 162,413 rows from seven named sources, 86,951 labelled 0 and 75,462 labelled 1. Aggregate audit found four blank or invalid rows, 930 duplicate normalized-for-whitespace bodies and zero conflicting exact body groups. TREC, Enron and Ling source names and binary labels do not independently establish phishing intent. It was excluded from fit and evaluation. The original script cleans it but fits the deployed text model on the first CSV. |
| SpamAssassin ham | `easy_ham` 2,499 of 2,500 and `hard_ham` 249 of 250 parsed bodies passed the usability filter for fit. A distinct `easy_ham_2` archive supplied 1,400 bodies before cross-source deduplication. Ham is legitimate mail under the publisher's selection. The corpus predates modern email and is weak coverage for short school and chat-like messages. |
| Nazario archives | Archive-labelled phishing, with 227/243 (2019), 233/247 (2022) and 405/419 (2023) usable bodies in fit. The 2024 archive supplied 381/403 usable bodies before deduplication for calibration and threshold selection. The archive can contain campaign repeats and malformed MIME. Message links remained input strings. |
| PhishFuzzer Manual | 3,300 published seed rows across all sources. The existing English Manual filter and duplicate screening yielded 87 legitimate and 88 phishing rows. These were reserved for holdout. Fit B additionally used 1,977 eligible non-Manual English seeds before screening. Fit and holdout share a publication in B, even after template grouping. Generated variants and spam were excluded. |
| Zenodo v3 short email/SMS | 2,000 published rows, including 100 records denoted `original_v1`. The two runs reserved those 100 as an outside-source holdout after excluding the 1,900 generated templates. Cross-cohort normalized exact screening retained 74 legitimate and 19 phishing. The data omit original header metadata. Seven records were removed by the duplicate screen. |
| Authored legitimate examples | 31 fit messages and 18 separate validation guard messages cover greetings, school, homework, conversational, professional and legitimate security advice. They were kept apart from the seven requested acceptance strings and do not count toward independent performance. |

The archived original CSV script makes a stratified random split. Reconstructing that split from the local CSV left **589 shared template groups covering 1,095 test rows** under the current normalized-edge heuristic. This indicates potential leakage and does not prove all groups are duplicates. The new runner removes cross-label normalized duplicates and groups shared first or last 12 normalized words across fit, validation and both holdouts. It reserves independent groups before calibration and tuning. Altered templates and unseen campaigns can evade this grouping. Exact fit provenance remains unknown for the shipped legacy artifact.

Study A combined the local legacy CSV and older named corpora. Its fit retained **16,521** messages (9,736 legitimate, 6,785 phishing) after screening. It excluded 3,058 exact duplicates, 2,160 cross-partition template matches, 533 rows in conflicting normalized groups and three unusable normalized bodies. Study B used the named corpora and public seeds, with **4,372** fit messages (2,866 legitimate, 1,506 phishing). B removed 405 exact duplicates, 841 cross-partition template matches and three unusable bodies. Each run divided 1,707 usable archive-validation records by template group into separate calibration and threshold-tuning folds. A split 913/794 and B split 787/920. There was zero overlap under the grouping rule between the two validation folds or across named partitions.

Sources and label descriptions are from the publishers. [Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/readme.html) · [Nazario phishing corpus](https://monkey.org/~jose/phishing/) · [PhishFuzzer sources and provenance](https://github.com/DataPhish/PhishFuzzer) · [Zenodo short-email validation corpus](https://zenodo.org/records/23954793)

## Threshold optimization and candidate design

The experiment tested word and character TF–IDF logistic regression, combined word and character TF–IDF logistic regression, calibrated linear SVM, and a hybrid logistic regression model. Word logistic regression used both unweighted and balanced fits. Regularization settings were fixed in the trial definitions. New text models normalized body and subject and replaced URLs, email addresses and digits with shape placeholders. The hybrid inferred bounded contextual features from label/destination comparisons, sender and Reply-To mismatch when present, URL evidence and message structure. Missing metadata became absent fields with explicit presence indicators. The learned model excluded grammar, so writing issues remain weak supporting evidence in the deployed policy. The original model always used its saved body preprocessing.

Every new candidate was sigmoid-calibrated using a separate validation fold. The runner swept thresholds on the tuning fold and locked the choice that maximized recall subject to at most 5% false positives on that fold and zero alerts on the 18 distinct benign guards. The table shows how deceptive the archive-only sweep can be. Its 0.25 cutoff reached 89.8% recall on A tuning. The independent test results below use the locked validation cutoff.

| Original raw cutoff on study A validation | Precision | Recall | F1 | FPR | FNR |
|---|---:|---:|---:|---:|---:|
| 0.25 | 84.1% | 89.8% | 86.8% | 3.9% | 10.2% |
| 0.50 | 96.9% | 63.3% | 76.5% | 0.5% | 36.7% |
| 0.60 | 96.3% | 53.7% | 69.0% | 0.5% | 46.3% |
| 0.70 | 98.3% | 40.1% | 57.0% | 0.2% | 59.9% |
| 0.80 | 95.5% | 14.3% | 24.9% | 0.2% | 85.7% |
| 0.871695, locked with benign guards | 100.0% | 8.8% | 16.3% | 0.0% | 91.2% |
| 0.90 | 100.0% | 7.5% | 13.9% | 0.0% | 92.5% |
| 0.95 | 100.0% | 2.0% | 4.0% | 0.0% | 98.0% |

These raw binary strategies have 100% prediction coverage and zero abstention. The archived original scored 0.526 average precision on the 175-message cohort, versus 0.942 on the A tuning fold. A's selected word/character SVM scored 0.990 average precision on tuning and 0.635 on the independent 175-message cohort. B's selected hybrid scored 0.996 on tuning and 0.577 on the 175. Calibration did not transfer. The corresponding Brier/ECE values and full precision-recall points are in the candidate results. Abstentions in the existing alert policy count as misses if the email is phishing, and coverage counts non-abstaining outcomes. No safety score is derived from a calibration bin. [Precision–recall plot](.runtime/email-model-study/precision-recall.png)

## Independent results and deployment decision

The comparison includes candidate-only thresholds and an offline combined policy that retains current alerts and adds a caution when a validation-selected candidate crosses its locked threshold. The final cohorts did not choose thresholds. Treat the 175-message cohort as a known recurring benchmark and the 93-message cohort as a separate source with a small positive count. The combined policies are evaluation experiments. They are not wired into the application.

| Cohort and strategy | Accuracy | Precision | Recall | F1 | FPR | FNR | TN / FP / FN / TP | Abstain |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| 175-message current alert policy | 52.6% | 85.7% | 6.8% | 12.6% | 1.1% | 93.2% | 86 / 1 / 82 / 6 | 0.6% |
| 175-message raw original at 0.50 | 52.0% | 51.5% | 79.5% | 62.5% | 75.9% | 20.5% | 21 / 66 / 18 / 70 | 0.0% |
| 175-message raw original, locked validation threshold A | 48.0% | 43.5% | 11.4% | 18.0% | 14.9% | 88.6% | 74 / 13 / 78 / 10 | 0.0% |
| 175-message A SVM + current evidence alerts | 58.3% | 74.2% | 26.1% | 38.7% | 9.2% | 73.9% | 79 / 8 / 65 / 23 | 0.0% |
| 175-message B hybrid + current evidence alerts | 42.3% | 44.9% | 64.8% | 53.0% | 80.5% | 35.2% | 17 / 70 / 31 / 57 | 0.0% |
| 93-message current alert policy | 79.6% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 74 / 0 / 19 / 0 | 11.8% |
| 93-message raw original at 0.50 | 65.6% | 36.2% | 89.5% | 51.5% | 40.5% | 10.5% | 44 / 30 / 2 / 17 | 0.0% |
| 93-message raw original, locked validation threshold A | 90.3% | 100.0% | 52.6% | 69.0% | 0.0% | 47.4% | 74 / 0 / 9 / 10 | 0.0% |
| 93-message A SVM + current evidence alerts | 95.7% | 100.0% | 78.9% | 88.2% | 0.0% | 21.1% | 74 / 0 / 4 / 15 | 10.8% |
| 93-message B hybrid + current evidence alerts | 87.1% | 63.0% | 89.5% | 73.9% | 13.5% | 10.5% | 64 / 10 / 2 / 17 | 10.8% |

| Fit / candidate | Threshold | Validation recall / FPR | 175 recall / FPR / precision | 93 recall / FPR / precision | Brier / ECE (175) | Batch ms/email (175) | Bytes |
|---|---:|---|---|---|---|---:|---:|
| A Original | 0.871695 | 8.8% / 0.0% | 11.4% / 14.9% / 43.5% | 52.6% / 0.0% / 100.0% | 0.309 / 0.214 | 0.054 | 932,628 |
| A Word LR | 0.998938 | 43.5% / 0.0% | 12.5% / 5.7% / 68.8% | 78.9% / 1.4% / 93.8% | 0.411 / 0.404 | 0.064 | 494,349 |
| A Balanced word LR | 0.998336 | 53.1% / 0.0% | 14.8% / 5.7% / 72.2% | 84.2% / 0.0% / 100.0% | 0.400 / 0.398 | 0.063 | 494,364 |
| A Character LR | 0.999449 | 42.2% / 0.0% | 11.4% / 1.1% / 90.9% | 73.7% / 0.0% / 100.0% | 0.422 / 0.428 | 0.375 | 632,282 |
| A Word + character LR | 0.998314 | 59.2% / 0.0% | 17.0% / 9.2% / 65.2% | 78.9% / 0.0% / 100.0% | 0.417 / 0.418 | 0.437 | 1,382,202 |
| A Word + character SVM | 0.996179 | 66.0% / 0.0% | 21.6% / 8.0% / 73.1% | 78.9% / 0.0% / 100.0% | 0.405 / 0.405 | 0.434 | 1,380,948 |
| A Hybrid LR | 0.999812 | 40.1% / 0.0% | 6.8% / 0.0% / 100.0% | 78.9% / 0.0% / 100.0% | 0.426 / 0.432 | 0.450 | 1,382,844 |
| B Original | 0.866602 | 7.5% / 0.0% | 11.4% / 14.9% / 43.5% | 52.6% / 0.0% / 100.0% | 0.309 / 0.214 | 0.054 | 932,628 |
| B Word LR | 0.943188 | 83.2% / 0.0% | 37.5% / 36.8% / 50.8% | 89.5% / 27.0% / 45.9% | 0.450 / 0.450 | 0.064 | 473,185 |
| B Balanced word LR | 0.935225 | 86.1% / 0.0% | 40.9% / 40.2% / 50.7% | 89.5% / 27.0% / 45.9% | 0.453 / 0.462 | 0.058 | 473,227 |
| B Character LR | 0.964173 | 79.8% / 0.0% | 36.4% / 25.3% / 59.3% | 89.5% / 13.5% / 63.0% | 0.431 / 0.429 | 0.357 | 582,872 |
| B Word + character LR | 0.932239 | 88.4% / 0.0% | 44.3% / 42.5% / 51.3% | 89.5% / 27.0% / 45.9% | 0.439 / 0.442 | 0.425 | 1,292,127 |
| B Word + character SVM | 0.877388 | 94.2% / 0.0% | 48.9% / 47.1% / 51.2% | 89.5% / 28.4% / 44.7% | 0.436 / 0.425 | 0.437 | 1,283,149 |
| B Hybrid LR | 0.657832 | 94.8% / 0.0% | 64.8% / 80.5% / 44.9% | 89.5% / 13.5% / 63.0% | 0.447 / 0.458 | 0.431 | 1,292,591 |

Every candidate row includes batch inference latency after preprocessing on the same machine. End-to-end scoring on the 175-message cohort with metadata averaged approximately **1.79 ms per message** for the current backend path in run A. The combined rows report alert decisions. They have no Brier or ECE value because a policy decision is not a probability distribution. Their coverage is 100% minus the abstain column.

The word/character SVM from A was the best validation-selected combined improvement that approached the false-positive budget on both test sources. It reached 26.1% recall on the 175, but had 9.2% false positives and 74.2% precision. A's character-only LR had the most promising conservative measured trade-off across both holdouts. It flagged 10/88 on the 175 with 1/87 false positives and 14/19 on the short corpus with 0/74 false positives. It was not the model selected on validation and still misses most phishing in the principal cohort. Promoting it based on its holdout results would turn that holdout into another tuning set. The B hybrid recovered more phishing examples, but its 80.5% false-positive rate on the 175 rules out promotion.

Previously trained candidates also had substantial cross-source issues. The original 175-row archived study reported recall/FPR of 38.6%/50.6% (word LR), 63.6%/80.5% (word+character LR), and 70.5%/87.4% (calibrated SVM). Their rescored runtime artifacts at fixed 0.50 on the 93-message outside-source cohort were 89.5%/37.8%, 100%/71.6%, and 100%/71.6% respectively. The smaller earlier word, character, and contextual models trained on part of the Manual seeds, so only their original 61-message grouped split is a relevant Manual comparison. On that split they measured recall/FPR of 37.1%/7.7%, 48.6%/3.8% and 100%/65.4% respectively. An evaluation on all 175 would mix their prior training data with test data. The older spam model is not the deployed phishing estimator. [Earlier model audit](V2_REPORT.md) · [Earlier scoring audit](FINAL_AUDIT.md)

## Regression, deployment and rollback

- The original four JavaScript tests and all 47 existing Python tests passed. Four added Python tests passed for a total of **51**. They verify threshold constraints and split isolation. They also cover the seven requested legitimate texts, three more legitimate messages, score bounds, the legacy response contract and a synthetic escalation with supporting header and link evidence.
- React browser smoke passed against the real loopback API in disposable Chrome. The actual installed unpacked build passed **21 detection, 12 false-positive and 16 compose interaction checks**. The separate 18/9/5 address matrix and the 16-category demo also passed. Chrome used a synthetic Gmail page and isolated SQLite databases. It did not open any URL from an evaluation corpus. Live Gmail and OAuth were outside the test.
- Both active artifacts loaded and produced predictions in the tested backend. Production continues to load `models/email_phishing_model.joblib` with the existing email policy in `backend/scoring.py`. No active artifacts, scoring logic, privacy code, Chrome assets or threat-store paths changed in this study. There is no migration or rollback needed. To return to the exact pre-study behavior, use the original backend and existing audited extension bundle, which remain the deployment inputs.
- Candidate artifacts and aggregate metrics are saved separately under `.runtime/email-model-study/production-comparison/` and `.runtime/email-model-study/source-diversity/`. Keep them off the deployment path. The files are pickle-based and their vocabularies were learned from source mail. Preserve the original artifact and an approved data/version manifest before any future replacement.

Reproduce the offline comparison from the repository root using the current project dependencies and the publisher files in the local study source directory. The optional historical-candidate argument loads only trusted local artifacts. Output directories must be new.

```sh
python -m training.email_recall_study .runtime/email-model-study/sources \
  .runtime/email-sources .runtime/email-model-study/reproduction-a \
  --legacy-csv /path/to/Phishing_Email.csv --archived-candidates .runtime/candidates

python -m training.email_recall_study .runtime/email-model-study/sources \
  .runtime/email-sources .runtime/email-model-study/reproduction-b --public-seeds
```

The source directory expects `seed.json`, the 2019, 2022, 2023 and 2024 labelled Nazario archives, `validation-v3.csv` and `validation-v3-meta.csv`. The ham directory expects the three SpamAssassin archives listed above. Aggregate outputs include dataset hashes, validation sweeps, raw calibration metrics, per-candidate confusion matrices and full precision-recall arrays. [Study A metrics](.runtime/email-model-study/production-comparison/evaluation.json) · [Study B metrics](.runtime/email-model-study/source-diversity/evaluation.json)

A defensible promotion needs a fresh, timestamp-separated cohort with representative modern legitimate messages and phishing from multiple sources, near-duplicate controls beyond edge matches, and enough negatives to estimate a low FPR by source. Metadata availability and false alarms on credible legitimate transactional mail should be validated before changing the risk policy. At the current stage SentinelAI's evidence-based alerts are suitable for a controlled demonstration. A low-alert result has limited protective value given the observed miss rate.
