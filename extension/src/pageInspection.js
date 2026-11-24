// This function is passed to chrome.scripting.executeScript as an isolated-world function.
export function inspectActiveDocument(action) {
  const key = '__sentinelPageObserver';
  const existing = globalThis[key];
  if (action === 'stop' && existing) {
    existing.stop();
    return { watching: false };
  }
  const visible = node => {
    const style = getComputedStyle(node);
    return node.getClientRects().length && style.display !== 'none' &&
      style.visibility === 'visible' && style.opacity !== '0';
  };
  const collect = () => {
    const features = {
      credential_forms: 0, payment_fields: 0, external_forms: 0, iframes: 0, external_frames: 0,
      external_links: 0, links: 0, buttons: 0, overlays: 0, infection_claim: 0,
      support_request: 0, prize_claim: 0, payment_request: 0, download_pressure: 0, countdown: 0,
      notification_prompt: 0, browser_impersonation: 0, blocking_overlay: 0,
      cross_site_navigation: 0, fullscreen: Number(Boolean(document.fullscreenElement)),
    };
    // Examine static structure only. Form values and editable text are excluded.
    const external = value => {
      try {
        const parsed = new URL(value, location.href);
        return /^https?:$/.test(parsed.protocol) && parsed.hostname !== location.hostname;
      } catch { return false; }
    };
    for (const form of [...document.forms].slice(0, 75)) {
      const password = form.querySelector('input[type="password"]');
      if (password && visible(password)) {
        features.credential_forms++;
        if (external(form.getAttribute('action') || location.href)) features.external_forms++;
      }
    }
    features.payment_fields = [...document.querySelectorAll('input[autocomplete^="cc-"]')].slice(0, 75).filter(visible).length;
    const frames = [...document.querySelectorAll('iframe')].slice(0, 75).filter(visible);
    features.iframes = frames.length;
    features.external_frames = frames.filter(frame => external(frame.getAttribute('src') || location.href)).length;
    const anchors = [...document.querySelectorAll('a[href]')].slice(0, 75).filter(visible);
    features.links = anchors.length;
    features.external_links = anchors.filter(link => external(link.getAttribute('href'))).length;
    features.buttons = [...document.querySelectorAll('button, [role="button"]')].slice(0, 75).filter(visible).length;
    const dialogs = [...document.querySelectorAll('dialog, [role="dialog"], [aria-modal="true"], [class*="overlay"], [class*="modal"]')].slice(0, 60).filter(visible);
    features.overlays = dialogs.length;
    features.blocking_overlay = Number(dialogs.some(node => {
      const { width, height } = node.getBoundingClientRect();
      return width > innerWidth * 0.70 && height > innerHeight * 0.65;
    }));
    const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
    let text = document.title.slice(0, 200);
    for (let n = 0; n < 300 && text.length < 7000 && walker.nextNode(); n++) {
      const node = walker.currentNode;
      const parent = node.parentElement;
      if (parent && !parent.closest('input, textarea, select, option, [contenteditable], [role="textbox"], script, style, template, noscript, pre, code')
          && node.length <= 10000 && visible(parent)) {
        text += ' ' + node.textContent.slice(0, 250);
      }
    }
    features.infection_claim = Number(/\b(?:virus detected|(?:computer|device) (?:is|has been) infected|malware detected)\b/i.test(text));
    features.support_request = Number(/\b(?:call (?:technical |tech )?support|call (?:this number|now)|contact (?:technical |tech )support)\b/i.test(text));
    features.prize_claim = Number(/\b(?:you (?:have )?won|claim your (?:prize|reward))\b/i.test(text));
    features.payment_request = Number(/\b(?:pay (?:now|a fee|shipping)|payment required|send (?:money|a gift card))\b/i.test(text));
    features.download_pressure = Number(/\b(?:download immediately|download now to (?:remove|protect|fix)|install now to protect)\b/i.test(text));
    features.countdown = Number(/\b(?:time remaining|offer expires)\b.{0,30}\b\d{1,2}:\d{2}\b/i.test(text));
    features.notification_prompt = Number(/\b(?:click allow|enable notifications)\b/i.test(text));
    features.browser_impersonation = Number(/\b(?:chrome security warning|windows defender alert|system security alert|browser security notice)\b/i.test(text));
    try {
      const navigation = performance.getEntriesByType('navigation')[0];
      features.cross_site_navigation = Number(Boolean(navigation?.redirectCount && document.referrer && external(document.referrer)));
    } catch { /* Optional browser metadata. */ }
    return features;
  };

  if (action === 'watch' && !existing) {
    let timer, expiry, last = '';
    const observer = new MutationObserver(() => {
      if (timer || document.visibilityState === 'hidden') return;
      timer = setTimeout(() => {
        timer = null;
        const observations = collect();
        const signature = JSON.stringify(observations);
        if (signature === last) return;
        last = signature;
        chrome.runtime.sendMessage({ type: 'PAGE_OBSERVATIONS', origin: location.origin, observations }).catch(() => {});
      }, 800);
    });
    let watch;
    const stop = () => {
      observer.disconnect();
      clearTimeout(timer);
      clearTimeout(expiry);
      delete globalThis[key];
      window.removeEventListener('pagehide', stop);
      if (watch) chrome.runtime.sendMessage({ type: 'PAGE_WATCH_STOPPED' }).catch(() => {});
    };
    watch = { stop };
    window.addEventListener('pagehide', stop, { once: true });
    expiry = setTimeout(stop, 10 * 60 * 1000);
    observer.observe(document.body || document.documentElement, {
      childList: true, subtree: true, characterData: true, attributes: true,
      attributeFilter: ['class', 'style', 'open', 'aria-hidden', 'hidden'],
    });
    globalThis[key] = watch;
  }
  return { watching: Boolean(globalThis[key]), origin: location.origin, observations: collect() };
}
