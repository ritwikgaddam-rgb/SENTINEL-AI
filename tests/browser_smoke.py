"""Exercise the restored React browser preview against the real loopback API."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Thread
import time
from urllib.request import urlopen

import websocket

from privacy_detector import privacy_report
from backend import server
from backend.assessments import PAGE_FEATURES


def wait(poll, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if value := poll():
            return value
        time.sleep(0.08)
    raise RuntimeError("The browser did not reach the expected test state.")


def serve(handler, port=0):
    service = ThreadingHTTPServer(("127.0.0.1", port), handler)
    Thread(target=service.serve_forever, daemon=True).start()
    return service


class QuietPreview(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class ChromePage:
    def __init__(self, connection):
        self.connection = connection
        self.sequence = 0

    def call(self, method, **params):
        self.sequence += 1
        self.connection.send(json.dumps({"id": self.sequence, "method": method, "params": params}))
        while True:
            response = json.loads(self.connection.recv())
            if response.get("id") == self.sequence:
                if "error" in response:
                    raise RuntimeError(response["error"])
                return response["result"]

    def evaluate(self, expression):
        result = self.call("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in result:
            raise RuntimeError(result["exceptionDetails"].get("exception", {}).get("description", expression))
        return result["result"].get("value")

    def has_text(self, text):
        return self.evaluate("document.body?.innerText.toLowerCase().includes(" + json.dumps(text.lower()) + ")")

    def button(self, label):
        assert self.evaluate("""(label => { const button = [...document.querySelectorAll('button')].find(
            button => button.textContent.trim() === label && !button.disabled);
            if (!button) return false; button.click(); return true; })(""" + json.dumps(label) + ")"), label

    def field(self, selector, value):
        self.evaluate("""((selector, value) => {
            const node = document.querySelector(selector);
            if (!node) throw new Error('Missing form control');
            Object.getOwnPropertyDescriptor(Object.getPrototypeOf(node), 'value').set.call(node, value);
            node.dispatchEvent(new Event('input', { bubbles: true }));
        })(""" + json.dumps(selector) + ", " + json.dumps(value) + ")")


def exercise_compose(page):
    editor = "document.querySelector('.editable')"
    rows = "document.querySelectorAll('.sentinel-compose-findings label:not(.sentinel-audit-marker-title) input')"
    trigger = "document.querySelector('.sentinel-compose-indicator img')"

    def expect(expression):
        wait(lambda: page.evaluate(expression))

    def draft(text):
        page.evaluate(f"{editor}.textContent = {json.dumps(text)}")
        page.evaluate(f"{editor}.dispatchEvent(new Event('input', {{bubbles:true}}))")

    def check_text(text):
        expect(f"{editor}.textContent === {json.dumps(text)}")

    expect(f"!!{trigger}")
    page.evaluate(f"{trigger}.click()")
    optional = "Aadhaar: 2345 6789 0122\nPhone: 1234567890\nCalculate 123456789012 + 1234567890."
    draft(optional + "\nEmail: demo@example.org")
    expect(f"{rows}.length === 3")
    assert page.evaluate(f"[...{rows}].map(i => i.checked)") == [False, False, True]
    page.button("Redact all")
    check_text(optional + "\nEmail: [EMAIL]")
    expect(f"{rows}.length === 2")
    assert page.evaluate("[...document.querySelectorAll('button')].find(b => b.innerText === 'Redact all').disabled")
    page.evaluate(f"{rows}[0].click()")
    page.button("Redact all")
    check_text(optional.replace("2345 6789 0122", "[AADHAAR]") + "\nEmail: [EMAIL]")

    markup = ('✨ I live in <b>Flat 402</b> at <i>Example Apartments</i> near Sample Park in Hyderabad.'
              ' <strong>Please reply.</strong> Email: demo@example.org')
    page.evaluate(f"{editor}.innerHTML = {json.dumps(markup)}")
    expect(f"{rows}.length === 2")
    page.button("Deselect all")
    page.evaluate(f"{rows}[0].click()")
    page.button("Redact selected")
    check_text("✨ I live in [ADDRESS]. Please reply. Email: demo@example.org")
    assert page.evaluate(f"{editor}.querySelector('b').textContent === '[ADDRESS]' && "
                         f"{editor}.querySelector('strong').textContent === 'Please reply.'")
    page.button("Undo")
    expect(f"{editor}.innerHTML === {json.dumps(markup)}")

    demo = (Path(__file__).resolve().parents[1] / "docs/privacy-demo-email.txt").read_text().strip()
    draft(demo)
    expect(f"{rows}.length === 16")
    assert page.evaluate(f"[...{rows}].every(i => i.checked)")
    assert page.evaluate("document.querySelectorAll('.sentinel-compose-findings .sentinel-audit-marker').length") == 16
    page.button("Redact all")
    check_text(privacy_report(demo)["redacted_text"])
    expect(f"{rows}.length === 0")
    page.button("Undo")
    check_text(demo)


def smoke(page, preview, api):
    page.call("Page.enable")
    page.call("Network.enable")
    page.call("Network.setBlockedURLs", urls=["http://127.0.0.1:8000/*", "http://localhost:8000/*"])
    page.call("Emulation.setDeviceMetricsOverride", width=390, height=580, deviceScaleFactor=1, mobile=False)
    page.call("Page.addScriptToEvaluateOnNewDocument", source="""
        const originalFetch = window.fetch.bind(window);
        window.fetch = (url, options) => {
          const standard = 'http://127.0.0.1:8000';
          if (window.fixtureOffline && typeof url === 'string' && url.startsWith(standard + '/')) {
            return Promise.reject(new TypeError('Synthetic backend offline'));
          }
          return originalFetch(typeof url === 'string' && url.startsWith(standard + '/')
            ? """ + json.dumps(api) + """ + url.slice(standard.length) : url, options);
        };
        Object.defineProperty(navigator, 'clipboard', {value: {writeText: async value => { window.testCopy = value; }}});
        window.testPost = (path, payload) => originalFetch(""" + json.dumps(api) + """ + path, {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
        }).then(response => {
            if (!response.ok) throw new Error(path + ': ' + response.status);
            return response.json();
        });
    """)
    page.call("Page.navigate", url=preview + "/popup.html")
    try:
        wait(lambda: page.has_text("% Safe"))
    except RuntimeError:
        output = page.evaluate("({page: location.href, hasTestPost: !!window.testPost, rendered: document.body?.innerText})")
        raise RuntimeError(f"Shield fixture could not see the expected API response: {output}") from None
    assert not page.has_text("Phishing Threat")
    assert not page.has_text("98% Safe")

    page.button("Email Guard")
    page.field("textarea.textarea-clean", "Hello")
    page.button("Analyze for Phishing & Leaks")
    wait(lambda: page.has_text("Insufficient information"))
    assert page.evaluate("!document.querySelector('.status-badge.danger')")
    page.field("textarea.textarea-clean", "Please reply with the verification code sent to your device.")
    page.button("Analyze for Phishing & Leaks")
    wait(lambda: page.has_text("Direct request for sensitive information"))
    assert page.evaluate("!!document.querySelector('.status-badge.danger')")

    page.button("Privacy")
    page.button("Insert Sample")
    wait(lambda: page.has_text("Safe Redacted Preview"))
    wait(lambda: page.has_text("[AADHAAR]"))
    page.button("Copy Safe Redacted Version")
    wait(lambda: page.evaluate("window.testCopy?.includes('[AADHAAR]')"))
    page.evaluate('document.querySelector(\'button[title="Scan & Audit History"]\').click()')
    wait(lambda: page.has_text("Email assessment"))
    page.evaluate('document.querySelector(\'button[title="Close History"]\').click()')

    privacy = page.evaluate("""window.testPost('/api/privacy-redact', {
        text: 'IBAN: GB82 WEST 1234 5698 7654 32.\\nOrder reference ID: 9876543210', preview: true
    })""")
    assert privacy["redacted_text"] == "IBAN: [IBAN].\nOrder reference ID: 9876543210"

    page.evaluate("window.syntheticSignals = " + json.dumps(dict.fromkeys(PAGE_FEATURES, 0)))
    page.evaluate("""
        const fixture = document.createElement('article');
        fixture.innerHTML = '<button>Dismiss</button><form><input type="password" value="synthetic-secret"></form>';
        document.body.appendChild(fixture);
        const report = () => {
            const overlay = fixture.querySelector('dialog[open]');
            const text = overlay?.textContent || '';
            const observations = {...window.syntheticSignals,
                credential_forms: fixture.querySelectorAll('form input[type=password]').length,
                overlays: Number(Boolean(overlay)),
                infection_claim: Number(/device infected/i.test(text)),
                support_request: Number(/call support/i.test(text))
            };
            return window.testPost('/api/scan-page', {url: 'https://example.org/', observations, preview: true});
        };
        window.firstPage = report();
        const watcher = new MutationObserver(() => {
            watcher.disconnect();
            window.changedPage = report();
        });
        watcher.observe(fixture, {childList: true});
        const overlay = document.createElement('dialog');
        overlay.open = true;
        overlay.textContent = 'Device infected. Call support.';
        fixture.appendChild(overlay);
    """)
    assert page.evaluate("window.firstPage")["risk_level"] == "neutral"
    wait(lambda: page.evaluate("!!window.changedPage"))
    result = page.evaluate("window.changedPage")
    assert result["assessment"] == "Suspicious"
    assert "synthetic-secret" not in json.dumps(result)
    page.button("Email Guard")
    page.field("textarea.textarea-clean", "Can we meet in the library tomorrow?")
    page.evaluate("window.fixtureOffline = true")
    page.button("Analyze for Phishing & Leaks")
    wait(lambda: page.has_text("Analysis unavailable"))
    assert not page.evaluate("!!document.querySelector('.status-badge.danger')")
    page.evaluate("window.fixtureOffline = false")
    # Exercise the compiled content script. The local preview substitutes only
    # the extension messaging transport and still runs the real privacy endpoint.
    page.evaluate("""document.body.innerHTML = '<div class="M9"><div class="editable Am Al" contenteditable="true"></div></div>';
        window.chrome.runtime = {id:'fixture', getURL:path => '/' + path,
            sendMessage: async ({text, selected}) => ({success:true, data:await window.testPost(
                '/api/privacy-redact', {text, selected, findings_only:selected === undefined,
                    preview:selected === undefined, context:'gmail_compose'})})};
        const content = document.createElement('script');
        content.src = '/content.js';
        document.body.appendChild(content);""")
    exercise_compose(page)
    print("Compose bulk consent, rich-text selective address redaction, undo and the full demo passed.")
    print("Browser preview and local HTTP API passed Shield, email, privacy copy, history and dynamic page fixtures.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="?", type=Path, default=Path("extension/dist"))
    args = parser.parse_args()
    if not (args.bundle / "popup.html").is_file():
        parser.error("Build the existing extension and supply the bundle directory.")
    chrome_bin = os.environ.get("SENTINELAI_CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    with tempfile.TemporaryDirectory(prefix="sentinel-browser-v2-") as directory:
        os.environ["SENTINELAI_DB_PATH"] = str(Path(directory) / "app.db")
        os.environ["SENTINELAI_THREATS_PATH"] = str(Path(directory) / "threats.db")
        server.init_db()
        api = serve(server.SentinelAPIHandler)
        try:
            front = serve(partial(QuietPreview, directory=args.bundle), 4173)
        except OSError:
            front = serve(partial(QuietPreview, directory=args.bundle), 5173)
        profile = Path(directory) / "chrome"
        chrome = subprocess.Popen([chrome_bin, "--headless=new", f"--user-data-dir={profile}", "--remote-debugging-port=0",
                                   "--disable-background-networking", "--disable-component-update", "--disable-sync",
                                   "--no-first-run", "--no-default-browser-check",
                                   "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost", "about:blank"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            info = profile / "DevToolsActivePort"
            wait(info.is_file)
            port = info.read_text().splitlines()[0]
            with urlopen(f"http://127.0.0.1:{port}/json/list", timeout=3) as response:
                target = next(item for item in json.load(response) if item["type"] == "page")
            connection = websocket.create_connection(target["webSocketDebuggerUrl"], suppress_origin=True, timeout=5)
            try:
                smoke(ChromePage(connection), f"http://127.0.0.1:{front.server_port}", f"http://127.0.0.1:{api.server_port}")
            finally:
                connection.close()
        finally:
            chrome.terminate()
            chrome.wait(timeout=10)
            for service in (front, api):
                service.shutdown()
                service.server_close()


if __name__ == "__main__":
    main()
