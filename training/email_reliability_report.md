# Email model reliability

The saved model scored `How are you` at **75.571294% phishing**. It scored `Hello` at **88.698357%**. The evidence policy now returns **Insufficient information** for both. It also leaves the model’s scores unchanged when there is enough evidence to report a result.

## Why the greeting was flagged

The fitted Logistic Regression classes are `[0, 1]`. Training maps `Safe Email` to `0` and `Phishing Email` to `1`, so the API had been reading the correct probability column. The vectorizer has 20,000 fitted features. It lowercases text and uses `(?u)\b\w\w+\b` for word tokenization with unigrams and bigrams. It uses raw term frequency, smoothed inverse document frequency, and L2 normalization. It has no stop-word filter, accent stripping, or custom preprocessing.

| Feature | TF-IDF weight | Coefficient for class 1 | Contribution to phishing log-odds |
| --- | ---: | ---: | ---: |
| `are` | 0.205005 | −0.575862 | −0.118055 |
| `are you` | 0.537845 | +0.679074 | +0.365237 |
| `how` | 0.324633 | +0.078418 | +0.025457 |
| `how are` | 0.729879 | +0.045800 | +0.033429 |
| `you` | 0.174886 | +5.060265 | +0.884968 |

The five features add about **+1.191036** log-odds to the intercept of **−0.061719**. The combined **+1.129318** produces the 75.57% score. With no recognized features the intercept alone produces **48.46%**. The greeting's score is driven by the fitted terms, especially `you` and `are you`. In the reconstructed training split, `you` occurred in 3,689 of 5,246 phishing bodies (70.3%) and 4,774 of 8,783 legitimate bodies (54.4%). L2 normalization lets a few terms carry all of the weight on short or poorly recognized input. The same issue applies to text with many words that the model does not recognize.

## Training data audit

The training script fits on `Phishing_Email.csv` using a random stratified 80/20 row split after dropping missing values and exact body duplicates. The training source is the [Phishing Emails dataset](https://www.kaggle.com/datasets/subhajournal/phishingemails/data), also available through the [dataset mirror](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset). The second local corpus, `train.parquet`, was exported to a cleaned CSV by the script and excluded from model fitting. Its positive labels cover general spam as well as phishing. [Seven Phishing Email Datasets data card](https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets)

| Source CSV stage | Legitimate | Phishing |
| --- | ---: | ---: |
| Before cleaning | 11,322 | 7,328 |
| After dropping missing bodies | 11,322 | 7,312 |
| After exact body deduplication | 10,979 | 6,558 |

The deduplicated corpus is 62.6% legitimate and 37.4% phishing. The fitted classifier uses the default unweighted loss. Reconstructing the original split found that **633 of 3,508 test rows (18.0%)** share a normalized body or template signature with rows used for fitting. F1 was 97.62% on that split and 97.18% after excluding overlaps. The saved model's F1 on the independent holdout was 70.80%. The gap indicates that the original corpus split gives a limited picture of generalization to new campaigns.

## Evidence policy and independent evaluation

The policy measures how much the TF-IDF vector depends on a few features. With feature weights `w`, the effective count is `(Σw²)² / Σw⁴`, which equals the number of nonzero features when their weights are equal and falls as the weights concentrate. A zero vector has zero effective features. The model abstains below **4.5 effective features**. The score threshold remains **0.50**, and scored results keep the model's unmodified probability. Grammar is separate from the model and the evidence policy.

| Benign or test fixture | Previous phishing score | Effective features | Current outcome |
| --- | ---: | ---: | --- |
| `How are you` | 75.57% | 2.62 | Insufficient information |
| `How are you today?` | 75.48% | 3.24 | Insufficient information |
| `Hello` | 88.70% | 1.00 | Insufficient information |
| `Hey` | 77.82% | 1.00 | Insufficient information |
| `Good morning` | 49.34% | 2.34 | Insufficient information |
| `Thank you` | 53.57% | 2.33 | Insufficient information |
| Existing benign school meeting test | 4.66% | 10.99 | Legitimate |
| Existing phishing test fixture | 95.51% | 12.74 | Phishing |

Threshold selection used 2,654 CEAS-08 legitimate bodies and 306 phishing bodies from Jose Nazario's 2024 hand-classified archive. The held-out evaluation used 2,102 TREC-07 legitimate bodies and 374 phishing bodies from the 2025 archive. Each ham source was sampled separately using a fixed random seed before screening. Screening excluded duplicates and heuristic campaign variants from the original labelled CSV, across partitions, and within each partition. It used Unicode case-folded tokenized bodies, versions with URLs, addresses and numbers replaced, and the first and last 40 tokens of those templates. Phishing emails are courtesy of Jose Nazario, CC BY 4.0. [Nazario archive and licence](https://monkey.org/~jose/phishing/), [ham corpus data card](https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets)

The candidate sweep included both stronger evidence requirements and higher phishing cutoffs. No candidate halved false alerts while keeping 90% of the original true detections on the selection set. The final selection minimized false positives subject to retaining at least 94% of baseline detections and classifying at least 90% of the selection set. The held-out results below use the thresholds selected without that set.

| Held-out metric | Before | With evidence policy |
| --- | ---: | ---: |
| False-positive rate over all legitimate emails | 3.04% | 2.71% |
| False-positive rate among scored legitimate emails | 3.04% | 2.83% |
| Phishing precision | 78.95% | 80.28% |
| Phishing recall | 64.17% | 62.03% |
| F1 | 70.80% | 69.98% |
| Coverage | 100.00% | 95.52% |

| Actual label and version | Predicted legitimate | Predicted phishing | Insufficient information |
| --- | ---: | ---: | ---: |
| Legitimate, before | 2,038 | 64 | 0 |
| Phishing, before | 134 | 240 | 0 |
| Legitimate, after | 1,957 | 57 | 88 |
| Phishing, after | 119 | 232 | 23 |

Abstained phishing counts as a missed detection for recall and F1. The evidence policy made seven fewer false reports and detected eight fewer phishing emails in the holdout. It abstained on 4.19% of legitimate emails and 6.15% of phishing emails. The overall selection-set FPR moved from 7.16% to 6.52% and recall from 58.17% to 54.90%, at 91.89% coverage.

The holdout Brier score for the raw probabilities was **0.0712** and log loss was **0.2605**. For scores between 0.80 and 1.00, mean raw confidence was 87.0% and observed phishing frequency was 77.1% on holdout. The same band averaged 88.6% against 37.5% observed on the selection set. The labels, prevalence, source, and collection dates differ across sets. These scores are model estimates, with calibration dependent on the population. The email sources and time periods are limited, and body signatures can miss related campaigns. The classifier has not been validated for SMS or iMessage. The fitted artifact remains unchanged because these data establish the need for broader training and validation but do not verify a better replacement.

## Reproduce

With the original `data/Phishing_Email.csv`, `data/train.parquet` and saved model, install PyArrow for Parquet input and download `phishing-2024` and `phishing-2025` from the archive into a local directory. Run the following from the repository root with those paths. The program extracts bodies locally, avoids attachments and link fetching, and prints aggregate results.

```sh
python -m training.evaluate_email /path/to/phishing-2024 /path/to/phishing-2025
```

| Artifact | SHA-256 |
| --- | --- |
| `email_phishing_model.joblib` | `bc4db63eaecad84be5b7380e41a68ef8e1b3e220815ad5bfa84f89c1287732bf` |
| `Phishing_Email.csv` | `18ef4fff1acb8986f0ab01e83ede6025420c829656af5a377560fce17e153b97` |
| `train.parquet` | `fbd955e65c2ced6181e9f3177fffd0aff32fd51a80d70eb174071037b477ec5c` |
| `phishing-2024` | `60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99` |
| `phishing-2025` | `f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f` |
