# SentinelAI

SentinelAI checks links and email text for phishing. It can also find and hide email addresses, Indian mobile numbers and Aadhaar-like numbers in text before you share it. All three scanners run on your computer using the files in this repository.

## Run the app

Use Python 3.11–3.13 and Node.js 22 or later with npm. The commands below use Python 3.13. Open two terminals in the project root. The saved models are included, so you can run the app without the training datasets or an API key.

**Terminal 1 — FastAPI**

```sh
python3.13 -m venv .runtime
source .runtime/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

If your interpreter has a different name, substitute its command on the first line. On Windows, use `py -3.13 -m venv .runtime` and activate it with `.runtime\Scripts\Activate.ps1` in PowerShell. Use this fresh environment because the older `.venv` in the repository points to a specific machine.

**Terminal 2 — React**

```sh
cd frontend
npm ci
npm run dev
```

Open [the dashboard](http://127.0.0.1:5173). Keep both terminals running. Vite forwards `/api` requests to FastAPI on port 8000. You can inspect requests, responses and input schemas in the [interactive API docs](http://127.0.0.1:8000/docs).

## Try it

1. Open **URL Scanner**, load the sample and scan it. Expand **URL characteristics** to see nine measurements of the submitted address. The score uses the host and path. The scanner reads the address string without opening it.
2. Open **Email Scanner**, paste a message or use the sample, then analyse it. Include the subject and body for more context. A brief greeting can return **Insufficient information**.
3. In **Privacy Scanner**, try `Email demo@example.org or call +91 9876543210.` Copy the redacted text and check that the surrounding sentence is intact.
4. Return to the dashboard to see the new totals and seven-day activity chart. **Scan History** lists scans newest first and can filter by scanner. It starts empty in a fresh database.

## How it works

| Scanner | Input and method | What the result means |
| --- | --- | --- |
| URL | `url_features.py` extracts nine values. The v3 gradient-boosted model uses a normalized address with the query and fragment removed. | The saved URL model uses **0** for phishing and **1** for legitimate. It preserves the column order in `url_features_v2.joblib`, including `NoOfDegitsInURL`. Scores between 25% and 85% return **Insufficient information**. |
| Email | The saved pipeline converts single words and adjacent pairs into TF-IDF features. Logistic regression classifies those features. | The email model uses **1** for phishing and **0** for legitimate. Both scanners look up the phishing class in `classes_` when reading probabilities. |
| Privacy | `privacy_detector.py` matches text patterns and replaces each match with `[EMAIL]`, `[PHONE]` or `[AADHAAR]`. | Category counts include repeated occurrences. Review the returned text before sharing. |

The models load once when FastAPI starts. The API labels a phishing prediction as high risk and a legitimate prediction as low risk. The privacy scanner reports medium risk for detected patterns and low risk for zero matches.

### Email writing and model evidence

`POST /scan/email` returns `analysis` with the TF-IDF evidence check, signed model contributions, observed warning signs and a separate writing check. For each displayed n-gram, the contribution is its TF-IDF value multiplied by the fitted logistic regression coefficient. Add the intercept and all contributions to reproduce the model's total log-odds. Writing findings and warning signs have no effect on the score.

The built-in English writing check flags a limited set of common grammar, spelling, repeated-word and punctuation issues. To opt into broader checks, run a standalone [LanguageTool HTTP server](https://dev.languagetool.org/http-server.html) locally. LanguageTool 6.6 and later require Java 17 or newer. From its extracted directory, run the following with an empty `server.properties` file or your own local configuration. [LanguageTool Java requirements](https://dev.languagetool.org/java-api)

```sh
java -cp languagetool-server.jar org.languagetool.server.HTTPServer --config server.properties --port 8081
```

Set `SENTINELAI_LANGUAGETOOL_PORT=8081` for FastAPI and restart it. Requests go to `127.0.0.1` with proxies and redirects disabled. The API uses the built-in check if the local service is unavailable. It accepts `language` values `en`, `en-US` and `en-GB` and reports `unsupported_language` for other values. The Apple Messages classifier uses the email model and skips the writing check. The model has not been validated specifically on SMS or iMessage.

### Scan history

Scored URL and email scans and completed privacy scans add rows to `scan_history.sqlite3` in the project root. History shows the timestamp, scanner, prediction, risk level and a generated summary. Submitted URLs, email bodies, authentication tokens, matched values, redacted text and explanation details stay out of history. Set `SENTINELAI_DB_PATH` before starting the API to use a separate database for a demo.

URL and email history uses the labels **Phishing** and **Legitimate**. SQLite stores confidence for the predicted class as a percentage from 0 to 100. The scan API returns `phishing_probability` as a fraction from 0 to 1 for scored predictions. An **Insufficient information** result has `phishing_probability: null`. The desktop monitor advances its message checkpoint after this result, and history counts only scored verdicts. Privacy history uses **Redacted** and **No matches** and stores the match count.

On startup, the API upgrades older tables in a single transaction at the existing database path. It preserves scan IDs and timestamps and uses generated summaries in place of legacy input previews. For older app rows, the migration recovers confidence from the rounded phishing probability in the summary when available. For rows from the teammate’s original schema, it interprets confidence values from 0 to 1 as fractions and larger values as percentages. The dashboard totals and history filters use the same API fields after migration.

The original SQLite module and database tests were contributed by a SentinelAI teammate.

## Project layout

| Path | Purpose |
| --- | --- |
| `main.py` | FastAPI startup, input validation, model predictions and API routes |
| `database.py` | SQLite history, filtering and dashboard counts |
| `models/` | Trained email classifier, URL classifiers and saved feature lists |
| `url_features.py`, `privacy_detector.py` | Original feature extractor and privacy matching functions |
| `training/` | Dataset preparation, training scripts and the original URL model check |
| `frontend/` | React and TypeScript pages, Tailwind CSS, Lucide icons and Vite config |
| `tests/` | API integration and database tests using temporary SQLite files |

## Check a build

With the Python environment active, run these commands from the project root. The tests exercise both model label mappings, privacy redaction, database migration, filtering and invalid inputs. They run against temporary SQLite files.

```sh
python -m unittest discover -s tests -v
python -m training.test_url_model_v2
```

From `frontend/`, run `npm run build` to type-check and bundle the UI. With the backend running, `npm run preview` serves that built bundle at [port 4173](http://127.0.0.1:4173).

## Limitations

A phishing prediction is based on patterns in the training data. A legitimate prediction can miss a harmful link or message. URL features omit page content and domain reputation. Email analysis uses the supplied text and does not authenticate the sender or inspect attachments. The separate `webpage_extractor.py` script is outside the API.

See the [URL evaluation](training/URL_EVALUATION.md) and [email evaluation](training/email_reliability_report.md) for the data, before-and-after metrics, probability calibration and reproduction commands. The URL model is suitable for human-reviewed triage and should not drive automatic blocking.

Privacy matching recognises specific formats. Names, postal addresses and uncommon phone formats can remain in the output. A twelve-digit match can be an ordinary number. History is shared by anyone using the same local API instance. The demo has no user accounts.
