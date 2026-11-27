"""Install the real unpacked extension. Only the Gmail document is a synthetic fixture.

Run with python -m tests.standalone_chrome BUILD [--replay PATH --results FILE].
Requires Chrome with the Extensions.loadUnpacked DevTools command and an unused port 8000.
"""
import argparse
import base64
from collections import Counter
from contextlib import contextmanager
import fcntl
from html import escape
import json
import os
from pathlib import Path
import select
import socket
from statistics import median
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from tests.browser_smoke import exercise_compose, wait
from backend import server

SITE = 'https://mail.google.com/sentinel-local-fixture'
CHROME = os.getenv('SENTINELAI_CHROME', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
CASES = [
    {"text": "The science club meets in the library after school. Bring a notebook.", "subject": "Club meeting"},
    {"text": "Please send your password.", "subject": "Account review"},
    {"text": "Our revised reading list is available. See the two resources below.", "subject": "Class resources",
     "links": [{"url": "https://example.org/read", "label": "Reading"}, {"url": "https://example.net/list", "label": "List"}]},
    {"text": "Hello", "subject": ""},
]
CONTEXT_CASES = json.loads((Path(__file__).parent / "fixtures/credential_context.json").read_text())


def listening():
    with socket.socket() as sock:
        return sock.connect_ex(('127.0.0.1', 8000)) == 0


def threat_api(path="", payload=None):
    request = Request("http://127.0.0.1:8000/api/threats" + path,
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={"Content-Type": "application/json"})
    with urlopen(request) as response:
        return json.load(response)


@contextmanager
def backend(history, threats):
    if listening():
        raise RuntimeError("Port 8000 is occupied. This test only stops its own backend.")
    env = os.environ | {"SENTINELAI_DB_PATH": str(history), "SENTINELAI_THREATS_PATH": str(threats)}
    p = subprocess.Popen([sys.executable, "backend/server.py", "8000"], env=env, stdout=subprocess.DEVNULL)
    try:
        wait(listening)
        with urlopen("http://127.0.0.1:8000/api/health") as r:
            assert json.load(r)["models_loaded"]["email_phishing"]
        yield
    finally:
        p.terminate()
        p.wait(10)
        assert not listening()


class Chrome:
    def __init__(self, directory):
        read, self.write = os.pipe()
        self.read, write = os.pipe()
        fds = [fcntl.fcntl(fd, fcntl.F_DUPFD, 8) for fd in (read, write)]
        os.close(read)
        os.close(write)
        cmd = ["/bin/bash", "-c", 'exec 3<&"$1" 4>&"$2"; shift 2; exec "$@"', "pipe", *map(str, fds),
               CHROME, "--headless=new", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
               "--disable-background-networking", "--disable-component-update", "--no-first-run", "--disable-sync",
               "--no-default-browser-check", "--proxy-server=http://127.0.0.1:9", "--proxy-bypass-list=localhost;127.0.0.1",
               "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
               f"--user-data-dir={directory}", "about:blank"]
        self.process = subprocess.Popen(cmd, pass_fds=fds, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for fd in fds:
            os.close(fd)
        self.buffer, self.seq, self.requests = b"", 0, []
        self.html = ''

    def close(self):
        self.send("Browser.close")
        self.process.wait(15)
        os.close(self.write)
        os.close(self.read)

    def send(self, method, session=None, **params):
        self.seq += 1
        msg = {"id": self.seq, "method": method, "params": params}
        if session:
            msg["sessionId"] = session
        os.write(self.write, json.dumps(msg).encode() + b"\0")
        return self.seq

    def call(self, method, session=None, **params):
        ident = self.send(method, session, **params)
        while True:
            while b"\0" not in self.buffer:
                if not select.select([self.read], [], [], 30)[0]:
                    raise TimeoutError(method)
                block = os.read(self.read, 65536)
                if not block:
                    raise RuntimeError("Chrome exited")
                self.buffer += block
            raw, self.buffer = self.buffer.split(b"\0", 1)
            m = json.loads(raw)
            if m.get("id") == ident:
                if "error" in m:
                    raise RuntimeError(str(m["error"]))
                return m["result"]
            if m.get("method") == "Fetch.requestPaused":
                req = m["params"]
                assert req["request"]["url"] == SITE and req["resourceType"] == "Document"
                self.send("Fetch.fulfillRequest", m["sessionId"], requestId=req["requestId"], responseCode=200,
                          responseHeaders=[{"name": "Content-Type", "value": "text/html; charset=utf-8"}],
                          body=base64.b64encode(self.html.encode()).decode())
            if m.get("method") == "Network.requestWillBeSent":
                req = m["params"]["request"]
                u = urlsplit(req["url"])
                self.requests.append((req["method"], u.scheme, u.hostname, u.path, m.get("sessionId") == getattr(self, "worker", None)))

    def setup(self, bundle):
        target = self.call("Extensions.loadUnpacked", path=str(bundle))["id"]
        self.ext = target
        self.popup = Page(self, f"chrome-extension://{target}/popup.html")
        self.popup.until("!!document.querySelector('button')")
        info = wait(lambda: next((t for t in self.call("Target.getTargets")["targetInfos"]
                                  if t["type"] == "service_worker" and t["url"].startswith("chrome-extension://" + target)), None))
        self.worker = self.call("Target.attachToTarget", targetId=info["targetId"], flatten=True)["sessionId"]
        self.call("Network.enable", self.worker)

    def scan(self, data, kind="email"):
        return self.popup.evaluate("chrome.runtime.sendMessage(" + json.dumps({"type": "SCREEN", "kind": kind, "input": data}) + ")")

    def gmail(self, cases):
        self.html = '<h2 class="hP">School inbox</h2>'
        for c in cases:
            links = ''.join('<a href="' + escape(k["url"]) + '">' + escape(k["label"]) + '</a>' for k in c.get("links", []))
            self.html += '<div class="adn ads"><div class="gE iv gt"><span class="gD" email="class@example.org">Class</span></div><div class="a3s">' + escape(c["text"]) + links + '</div></div>'
        self.html += '<div class="M9"><div class="Am Al editable" contenteditable="true" aria-label="Message Body"></div></div>'
        page = Page(self, SITE)
        page.until(f"document.querySelectorAll('.sentinel-gmail-bar').length >= {len(cases)}")
        return page


class Page:
    def __init__(self, chrome, url):
        self.chrome = chrome
        tid = chrome.call("Target.createTarget", url="about:blank")["targetId"]
        self.session = chrome.call("Target.attachToTarget", targetId=tid, flatten=True)["sessionId"]
        chrome.call("Network.enable", self.session)
        if url == SITE:
            chrome.call("Fetch.enable", self.session, patterns=[{"urlPattern": SITE, "resourceType": "Document"}])
        chrome.call("Page.navigate", self.session, url=url)

    def evaluate(self, expression):
        r = self.chrome.call("Runtime.evaluate", self.session, expression=expression, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in r:
            raise RuntimeError(r["exceptionDetails"].get("exception", {}).get("description", "Browser script failed"))
        return r["result"].get("value")

    def until(self, expression):
        return wait(lambda: self.evaluate(expression))

    def field(self, selector, value):
        self.evaluate("""((selector, text) => { const el = document.querySelector(selector);
          Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value').set.call(el, text);
          el.dispatchEvent(new Event('input', {bubbles:true})); })(""" + json.dumps(selector) + "," + json.dumps(value) + ")")

    def button(self, label):
        self.evaluate("[...document.querySelectorAll('button')].find(b => b.textContent.trim() === " + json.dumps(label) + ").click()")


def verify_privacy_matrix(page):
    from tests.test_privacy_numbers import DETECTIONS, NEGATIVES
    from tests.test_residential_addresses import CASES as addresses, NEGATIVE, REVIEW
    from privacy_detector import PLACEHOLDERS
    rows = [(f"{label}: {value}", kind, True) for label, value, kind in DETECTIONS]
    rows += [(text, kind, False) for text, kind in NEGATIVES]
    rows += [(a + b + c, "addresses", True) for a, b, c in addresses]
    rows += [(text, None, False) for text in NEGATIVE] + [(text, "addresses", False) for text in REVIEW]
    editor = "document.querySelector('.editable')"
    panel = "document.querySelector('.sentinel-compose-panel')"
    inputs = "document.querySelectorAll('.sentinel-compose-findings label:not(.sentinel-audit-marker-title) input')"
    page.evaluate(f"if ({panel}.hidden) document.querySelector('.sentinel-compose-indicator img').click()")
    for text, kind, checked in rows:
        page.evaluate(f"{editor}.textContent={json.dumps(text)};{editor}.dispatchEvent(new Event('input',{{bubbles:true}}))")
        page.until(f"!{panel}.innerText.includes('Checking draft') && {inputs}.length === {int(bool(kind))}")
        if kind:
            category = json.dumps(PLACEHOLDERS[kind][1:-1])
            page.until(f"document.querySelector('.sentinel-compose-findings .sentinel-audit-marker-title')?.textContent.includes({category})")
            assert page.evaluate(f"{inputs}[0].checked") == checked
        assert page.evaluate(f"{editor}.textContent") == text
    print("Installed compose matrix passed 21 detection, 12 false-positive and 32 address cases.", flush=True)


def run(bundle, replay, results):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        profile = tmp / "chrome"
        browser = Chrome(profile)
        try:
            with backend(tmp / "history.db", tmp / "threats.db"):
                browser.setup(bundle)
                assert browser.scan(CASES[0])["inference_source"] == "loopback"
                for case in CONTEXT_CASES:
                    result = browser.scan(case)
                    assert (result["inference_source"], result["risk_level"]) == ("loopback", case["expected"]), case["case"]
                assert threat_api()["samples"] == []
                threat_api("/settings", {"enabled": True, "sanitized_text_enabled": True})
                connected_gmail = browser.gmail([CONTEXT_CASES[i] for i in (0, 3, 4)])
                classes = connected_gmail.evaluate("[...document.querySelectorAll('.adn .sentinel-gmail-bar')].map(b => b.className.split(' ').at(-1))")
                assert classes == ["safe", "unknown", "danger"], classes
                browser.gmail([CONTEXT_CASES[4]])
                sample, = threat_api()["samples"]
                assert sample["kind"] == "email" and sample["label"] is None and sample["sanitized_body"] is None
                url = browser.scan({"url": "https://account.example@elsewhere.example/review"}, "url")
                assert url["persistence"]["collection"] == "saved"
                assert threat_api()["counts"] == {"pending": 2}
                compose = browser.gmail(CASES[:1])
                exercise_compose(compose)
                verify_privacy_matrix(compose)
            assert not listening()
            assert not subprocess.run(["lsof", "-nP", "-iTCP:8000", "-sTCP:LISTEN"], capture_output=True).stdout
            r = browser.scan(CASES[1])
            assert r["inference_source"] == "packaged_model" and r["risk_level"] == "danger"
            assert r["persistence"]["collection"] == "unavailable"
            gmail_cases = [CONTEXT_CASES[i] for i in (0, 3, 4)]
            page = browser.gmail(CASES + gmail_cases)
            classes = page.evaluate("[...document.querySelectorAll('.adn .sentinel-gmail-bar')].map(b => [b.className,b.querySelector('.sentinel-bar-score').textContent])")
            expected = ['safe', 'danger', 'safe', 'unknown', *(c['expected'] for c in gmail_cases)]
            assert expected == [x[0].split()[-1] for x in classes], classes
            assert all(x[1].startswith('Risk index ') and x[1].endswith('/100') for x in classes[:3])
            assert classes[3][1] == 'Score unavailable' and classes[5][1] == 'Score unavailable'
            print("Offline Gmail fixture", classes, flush=True)
        finally:
            browser.close()

        browser = Chrome(profile)
        try:
            browser.setup(bundle)
            t = time.perf_counter()
            first = browser.scan(CASES[1])
            cold = 1000 * (time.perf_counter() - t)
            assert first["ml_evaluated"] and first["inference_source"] == "packaged_model"
            assert any(x[3].endswith('models/screening.json') for x in browser.requests)
            browser.popup.button("Email Guard")
            if not browser.popup.evaluate("Boolean(chrome.runtime.getManifest().oauth2)"):
                browser.popup.until("""[...document.querySelectorAll('button')].some(
                    button => button.textContent.trim() === 'Sign in with Google' && button.disabled
                )""")
            browser.popup.field("textarea.textarea-clean", CASES[1]["text"])
            browser.popup.button("Analyze for Phishing & Leaks")
            browser.popup.until("document.querySelector('.status-badge.danger') && document.querySelector('.score-pill').textContent.startsWith('Risk index ')")
            mark = len(browser.requests)
            for c in CASES:
                r = browser.scan(c)
                expected = server.predict_email_risk(c['text'], links=c.get('links', []), subject=c['subject'])
                assert r["risk_level"] == expected["display_level"] and r["safety_score"] == expected["safety_score"]
                assert abs(r["model_observation"]["phishing_probability"] - expected["model_observation"]["phishing_probability"]) < 1e-12
            for case in CONTEXT_CASES:
                r = browser.scan(case)
                assert (r["inference_source"], r["risk_level"]) == ("packaged_model", case["expected"]), case["case"]
                if r["safety_score"] is not None:
                    assert any(m["id"] == "score_meaning" for m in r["markers"])
            assert len(browser.scan(CASES[2])["links"]) == 2
            for url in ('https://www.amazon.com/', 'https://www.flipkart.com/', 'https://www.youtube.com/', 'https://example.org/test'):
                r = browser.scan({"url": url}, "url")
                assert r["inference_source"] == "packaged_model" and r["risk_score"] == server.predict_url_risk(url)["risk_score"]
            perf = browser.call("Runtime.evaluate", browser.worker, expression="performance.getEntriesByName('sentinel-model-load').at(-1)?.duration", returnByValue=True)["result"]["value"]
            assert perf and perf > 0
            heap = browser.call("Runtime.getHeapUsage", browser.worker)["usedSize"]
            before = browser.call("SystemInfo.getProcessInfo")["processInfo"]
            times = []
            for _ in range(50):
                t = time.perf_counter()
                browser.scan(CASES[0])
                times.append(1000 * (time.perf_counter() - t))
            after = {p["id"]: p["cpuTime"] for p in browser.call("SystemInfo.getProcessInfo")["processInfo"]}
            cpu = sum(after.get(p["id"], p["cpuTime"]) - p["cpuTime"] for p in before)
            assert not [r for r in browser.requests[mark:] if r[1] in ("http", "https")]
            report = {"port_8000_empty": True, "cold_ms": cold, "model_load_ms": perf, "warm_median_ms": median(times), "worker_heap_bytes": heap,
                      "chrome_cpu_seconds_50_scans": cpu, "scores": classes, "cold_requests": browser.requests[:mark],
                      "warm_http_requests": 0}
            if replay:
                from collections import defaultdict
                from training.context_study import stats
                import numpy as np
                rows = [json.loads(s) for s in replay.read_text().splitlines()]
                scored = defaultdict(list)
                python_times = []
                for start in range(0, len(rows), 8):
                    batch = rows[start:start+8]
                    # Gmail truncates by UTF-16 units. Feed both scanners the same
                    # bounded message and leave any partial surrogate out of it.
                    inputs = [dict(text=r["body"].encode("utf-16-le", "surrogatepass")[:40000].decode("utf-16-le", "ignore"),
                                   subject=r["subject"], sender=r["sender"], links=r["links"], reply_to=r["reply_to"])
                              for r in batch]
                    out = browser.popup.evaluate("""(async inputs => {const out = []; for (const input of inputs) {
                        const r = await chrome.runtime.sendMessage({type:'SCREEN',kind:'email',input});
                        out.push([r.risk_level,r.risk_score,r.model_observation?.phishing_probability,r.inference_source]);} return out;} )(""" + json.dumps(inputs) + ")")
                    for r, x, js in zip(batch, inputs, out):
                        assert js[3] == "packaged_model" and js[2] is not None, (r["set"], start)
                        started = time.perf_counter()
                        py = server.predict_email_risk(x["text"], x["sender"], x["links"], x["subject"], x["reply_to"])
                        python_times.append((time.perf_counter() - started) * 1000)
                        scored[r["set"]].append([r["label"], js[0], py["display_level"], js[2], py["model_observation"]["phishing_probability"], js[1], py["risk_score"]])
                report["python_median_ms"] = median(python_times)
                for cohort, pairs in scored.items():
                    y, js, py, pj, pp, sj, sp = zip(*pairs)
                    sub = stats(y, [v in ("danger","suspicious") for v in js])
                    sub["display_by_label"] = {
                        label: dict(Counter(level for actual, level in zip(y, js) if actual == value))
                        for value, label in ((0, "legitimate"), (1, "phishing"))
                    }
                    sub.update(raw=stats(y, np.array(pj) > .5, np.array(pj)), max_probability_error=float(max(abs(a-b) for a,b in zip(pj,pp))),
                               verdict_differences=sum(a!=b for a,b in zip(js,py)), risk_differences=sum(a!=b for a,b in zip(sj,sp)),
                               max_risk_error=max((abs(a-b) for a,b in zip(sj,sp) if a is not None and b is not None), default=0),
                               abstentions=Counter(js)["unknown"])
                    report[cohort] = sub
                    assert sub["max_probability_error"] < 1e-12, cohort
                    assert sub["verdict_differences"] == sub["risk_differences"] == 0, cohort
            print("HTTP activity by method, host, path and worker context", Counter(r for r in browser.requests if r[1] in ('http','https')), flush=True)
            if results:
                results.write_text(json.dumps(report, indent=2))
            assert all(r[2] in ('localhost','127.0.0.1') and r[3] == '/api/health' for r in browser.requests if r[4] and r[1] in ('http','https'))
            report["offline_network"] = dict(Counter(r[3] for r in browser.requests if r[1] in ("http","https")))
            invalid = tmp / "regular-file"
            invalid.touch()
            with backend(invalid / "history.db", invalid / "threats.db"):
                wait(lambda: browser.scan(CASES[0])["inference_source"] == "loopback", timeout=12)
                persisted = browser.scan(CASES[1])
                assert persisted["persistence"]["history"] == "unavailable" and persisted["risk_level"] == "danger"
                assert persisted["persistence"]["collection"] == "unavailable"
            with backend(tmp / "history.db", tmp / "threats.db"):
                wait(lambda: browser.scan(CASES[0])["inference_source"] == "loopback", timeout=12)
                resumed = browser.scan({"text": "Please reply with your password to confirm the different fixture."})
                assert resumed["persistence"]["collection"] == "saved"
                assert threat_api()["counts"] == {"pending": 3}
            if results:
                results.write_text(json.dumps(report, indent=2))
            print("Chrome restart, recovery, unavailable SQLite, local URL model and zero warm scan network requests passed.", flush=True)
        finally:
            browser.close()


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("bundle", type=Path)
    cli.add_argument("--replay", type=Path)
    cli.add_argument("--results", type=Path)
    args = cli.parse_args()
    run(args.bundle.resolve(), args.replay, args.results)
