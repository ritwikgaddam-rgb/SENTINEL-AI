# URL classifier reliability

The bundled v2 forest labelled 15,820 of 15,833 independently labelled benign URLs as phishing. All 134,850 legitimate PhiUSIIL training rows used HTTPS, began with `www.`, and had neither a path nor a query. The forest learned that dataset fingerprint. Adding `/` to the Flipkart root changed only `URLLength` from 24 to 25, and the phishing estimate jumped from 0.37% to 100%. Ordinary paths, bare hostnames and query strings also produced false positives. No exact earlier scan URL was available from the metadata-only history. [Original dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)

Both saved models have `classes_ = [0, 1]` with `0` phishing and `1` legitimate. The original API took column `classes_.index(0)`, and direct results agreed with the pre-change API on the reported roots and checked search variants. V2's feature order matches its saved column list. All nine recomputed integer features match `data/url_training_data.csv` across all 235,795 source rows. The published PhiUSIIL columns are a separate representation. The earlier legacy training script flipped labels and trained with those published columns. The FastAPI URL route used v2. The source contains 425 duplicate URLs and 241 identical nine-number feature signatures shared by examples of both classes. V2's source-domain split could not prevent shortcuts shared across domains.

## Features

The order below applies to v2, v3 and the feature lists in the examples. V2 counts characters in the trimmed input. V3 uses the same extractor on a URL with normalized root spelling and its query and fragment removed. The API returns the observed original features separately.

| Feature | Definition in the repository | Rows matching the published column |
|---|---|---:|
| `URLLength` | Python character count for the full input, including scheme | 48,644 |
| `DomainLength` | Character count of the hostname, excluding credentials and port | 235,759 |
| `IsDomainIP` | 1 if Python `ip_address` accepts the hostname | 235,765 |
| `NoOfSubDomain` | Dot-separated hostname labels minus two, with a minimum of zero. This is an estimate for multi-label public suffixes and IPs. | 235,787 |
| `NoOfLettersInURL` | Characters accepted by `str.isalpha()` across the input | 0 |
| `NoOfDegitsInURL` | Characters accepted by `str.isdigit()` across the input. The spelling matches the saved columns. | 234,584 |
| `NoOfQMarkInURL` | Literal `?` count | 235,783 |
| `NoOfAmpersandInURL` | Literal `&` count | 232,623 |
| `IsHTTPS` | 1 if the parsed scheme is `https` | 235,302 |

The recomputed length exceeded the published length by one on 187,149 rows, including every legitimate row. The recomputed letter count exceeded the published count by nine on 134,846 legitimate rows. Simple scheme removal did not reproduce the published values. The source material and CSV establish the discrepancies and the v2 preparation logic, while leaving the full upstream feature-generation rules unresolved.

## Corrected classifier and evaluation

V3 is a 150-iteration gradient-boosted tree classifier trained on 58,207 PhreshPhish URLs from 27,297 domain groups. The training set includes 32,675 legitimate URLs with paths. It includes 3,602 phishing URLs with queries and only 12 benign URLs with queries, so query and fragment text were excluded to reduce this collection bias. A bare root and a root with `/` produce the same features. The validation split supported returning a high verdict from a score of 0.85 and a low verdict up to 0.25 under development targets of at most 2% alerts per benign URL and 7.5% phishing among low verdicts. V3 otherwise returns `Insufficient information` with a null score. Returned scores are the model's phishing-class estimates. [PhreshPhish paper](https://arxiv.org/abs/2507.10854), [dataset and licence](https://huggingface.co/datasets/phreshphish/phreshphish)

The evaluation removed invalid records and duplicate URL spellings, conservatively grouped hosts by their final two labels, and excluded all groups found in the original PhiUSIIL file from PhreshPhish. The resulting groups were split using fixed seeds 42 and 43. Train, validation and test groups are disjoint. The held-out test set contains 27,139 URLs in 13,649 groups, including 14,248 labelled legitimate URLs with paths and seven with queries. Counts for legitimate query URLs are too small to estimate their false-positive rate reliably. The split also cannot rule out all related campaigns hosted on different domains. URLs were processed offline without contacting any listed host.

| Model on identical PhreshPhish test URLs | Coverage | Accuracy | Precision | Recall | F1 | False-positive rate | False-negative rate | Confusion matrix `[[TN, FP], [FN, TP]]` |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| V2 | 100% | 35.33% | 37.71% | 84.70% | 52.18% | 99.92% | 15.30% | `[[13, 15820], [1730, 9576]]` |
| V3 forced binary at 0.5 | 100% | 80.94% | 75.60% | 80.08% | 77.78% | 18.46% | 19.92% | `[[12911, 2922], [2252, 9054]]` |
| V3 with abstention | 57.81% | 91.96% | 94.86% | 82.54% | 88.27% | 2.59% | 17.46% | `[[9681, 257], [1004, 4746]]` |

The last row's accuracy, recall, F1 and error rates describe verdicts. Including abstentions, the release policy flags 1.62% of all benign URLs and detects 41.98% of all phishing URLs. It abstains on 5,895 benign and 5,556 phishing URLs. Brier score over all raw scores improved from 0.644 to 0.135, and ROC AUC from 0.392 to 0.888. Predicted percentages are dependent on the benchmark population. Calibration for a field population with a much lower phishing rate is unverified.

LegitPhish was a cross-source check. It shares at least 36,936 benign URLs verbatim with PhiUSIIL. Excluding both original and PhreshPhish domain groups leaves 23 legitimate and 59,030 phishing URL labels. V2 issued 23 false alarms and detected all 59,030 phishing labels. V3 issued zero false alarms, abstained on 14 of the 23 benign URLs, and detected 56,689 phishing labels. This cross-check is strongly skewed toward phishing and provides limited independent benign coverage. [LegitPhish source dataset](https://doi.org/10.17632/hx4m73v2sf.1)

## Before and after examples

V2's predicted class maps directly to its API verdict. V3's raw scores are included for debugging. The final two columns are the actual response from FastAPI using a temporary database. The lookalike uses the reserved `.invalid` suffix and the IP is a private local address. Their rows exercise the prediction path without asserting ground truth.

| URL | Observed features in saved order | V2 class | V2 P(phishing), P(legitimate) | V3 P(phishing), P(legitimate) | New API verdict | New API P(phishing) |
|---|---|---:|---|---|---|---:|
| `https://www.flipkart.com` | `24,16,0,1,19,0,0,0,1` | 1 | 0.003745, 0.996255 | 0.531566, 0.468434 | Insufficient information | null |
| `https://www.flipkart.com/` | `25,16,0,1,19,0,0,0,1` | 0 | 1.000000, 0.000000 | 0.531566, 0.468434 | Insufficient information | null |
| `https://www.flipkart.com/s?k=headphones&sort=price` | `50,16,0,1,40,0,1,1,1` | 0 | 1.000000, 0.000000 | 0.492407, 0.507593 | Insufficient information | null |
| `https://www.flipkart.com/search?q=wireless+headphones` | `53,16,0,1,44,0,1,0,1` | 0 | 1.000000, 0.000000 | 0.439813, 0.560187 | Insufficient information | null |
| `https://www.amazon.in` | `21,13,0,1,16,0,0,0,1` | 1 | 0.003264, 0.996736 | 0.403423, 0.596577 | Insufficient information | null |
| `https://www.amazon.in/s?k=headphones` | `36,13,0,1,28,0,1,0,1` | 0 | 1.000000, 0.000000 | 0.387194, 0.612806 | Insufficient information | null |
| `https://www.amazon.com` | `22,14,0,1,17,0,0,0,1` | 1 | 0.001915, 0.998085 | 0.435612, 0.564388 | Insufficient information | null |
| `https://www.amazon.com/dp/B0D1XD1ZV3` | `36,14,0,1,25,4,0,0,1` | 0 | 1.000000, 0.000000 | 0.460823, 0.539177 | Insufficient information | null |
| `https://www.youtube.com` | `23,15,0,1,18,0,0,0,1` | 1 | 0.003194, 0.996806 | 0.468882, 0.531118 | Insufficient information | null |
| `https://www.youtube.com/results?search_query=computer+science` | `61,15,0,1,51,0,1,0,1` | 0 | 1.000000, 0.000000 | 0.439738, 0.560262 | Insufficient information | null |
| `https://www.google.com` | `22,14,0,1,17,0,0,0,1` | 1 | 0.001915, 0.998085 | 0.435612, 0.564388 | Insufficient information | null |
| `https://www.google.com/search?q=sentinelai` | `42,14,0,1,34,0,1,0,1` | 0 | 1.000000, 0.000000 | 0.400833, 0.599167 | Insufficient information | null |
| `https://www.wikipedia.org` | `25,17,0,1,20,0,0,0,1` | 1 | 0.002717, 0.997283 | 0.686364, 0.313636 | Insufficient information | null |
| `https://en.wikipedia.org/wiki/Computer_security` | `47,16,0,1,39,0,0,0,1` | 0 | 1.000000, 0.000000 | 0.030831, 0.969169 | Legitimate | 0.030831 |
| `https://github.com` | `18,10,0,0,14,0,0,0,1` | 0 | 1.000000, 0.000000 | 0.779233, 0.220767 | Insufficient information | null |
| `https://github.com/ritwikgaddam-rgb/SENTINALAI` | `46,10,0,0,39,0,0,0,1` | 0 | 1.000000, 0.000000 | 0.105828, 0.894172 | Legitimate | 0.105828 |
| `https://stackoverflow.com` | `25,17,0,0,21,0,0,0,1` | 0 | 1.000000, 0.000000 | 0.758635, 0.241365 | Insufficient information | null |
| `https://stackoverflow.com/questions/tagged/python` | `49,17,0,0,42,0,0,0,1` | 0 | 1.000000, 0.000000 | 0.165199, 0.834801 | Legitimate | 0.165199 |
| `https://docs.github.com/en/get-started` | `38,15,0,1,30,0,0,0,1` | 0 | 1.000000, 0.000000 | 0.059760, 0.940240 | Legitimate | 0.059760 |
| `http://192.168.1.1/login` | `24,11,1,2,9,8,0,0,0` | 0 | 1.000000, 0.000000 | 0.999365, 0.000635 | Phishing | 0.999365 |
| `https://www.flipkart.com.example.invalid/s?k=headphones` | `55,32,0,3,45,0,1,0,1` | 0 | 1.000000, 0.000000 | 0.885389, 0.114611 | Phishing | 0.885389 |

The API distinguishes observed URL features from its probability estimate. It does not attribute predictions to individual features or verify a website's identity, contents or redirects. HTTPS is an observed property of the address.

## Reproduce

Use scikit-learn 1.7.2 and the raw CSV from [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), the [URL-only PhreshPhish v1.0.1 export](https://github.com/aI-area/PhishDetecting/tree/main/dataset/PhreshPhish), and [LegitPhish version 1](https://data.mendeley.com/datasets/hx4m73v2sf/1). Only model artifacts ship with the application. The raw datasets can stay under the ignored `data/` directory.

```sh
python -m training.evaluate_url_models \
  --phiusiil data/PhiUSIIL_Phishing_URL_Dataset.csv \
  --phreshphish data/phreshphish_test.csv.gz \
  --legitphish data/legitphish.csv \
  --output /tmp/sentinel-url-v3-reproduced.joblib
```

| File | SHA-256 |
|---|---|
| `PhiUSIIL_Phishing_URL_Dataset.csv` | `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` |
| `phreshphish_test.csv.gz` | `ecc1efc3a8207f91b3953546011da5f35bc17907e7ae96ada6beb6635efa6dd7` |
| `legitphish.csv` | `8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd` |
| `url_phishing_model_v2.joblib` | `b7095d37fcfc23e8708469be58251eb4bdd8cdcfabe53f00be3167559bb12384` |
| `url_phishing_model_v3.joblib` | `47a66af5c5807619f30bbb0bf4738975c157798f9cc4347dc52686b373872ece` |
