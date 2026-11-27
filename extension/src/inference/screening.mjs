// Inference uses packaged numeric parameters. Email content never leaves this module.
const sigmoid = value => 1 / (1 + Math.exp(-value));
const round1 = n => Math.round(n * 10) / 10;
const size = s => [...s].length;
const words = /[\p{L}\p{N}_]+/gu;
const webLink = /https?:\/\/[^\s<>"']+/gi;
const trimLink = s => s.replace(/[.,;!?)]+$/, '');

function featureKey(term) {
  let a = 2166136261, b = 5381;
  for (const c of term) {
    a = Math.imul(a ^ c.codePointAt(0), 16777619);
    b = Math.imul(b, 33) + c.codePointAt(0);
  }
  return [a, b].map(n => (n >>> 0).toString(16).padStart(8, '0')).join('');
}

function emailProbability(body, model) {
  const tokens = (body.toLowerCase().match(words) || []).filter(t => size(t) >= 2);
  const counts = new Map();
  for (let i = 0; i < tokens.length; ++i) {
    const unigram = tokens[i];
    counts.set(unigram, 1 + (counts.get(unigram) || 0));
    if (i > 0) {
      const bigram = tokens[i - 1] + ' ' + unigram;
      counts.set(bigram, 1 + (counts.get(bigram) || 0));
    }
  }
  let dot = 0, squares = 0;
  for (const [term, count] of counts) {
    const weights = model.terms[featureKey(term)];
    if (!weights) continue;
    const tfidf = count * weights[0];
    squares += tfidf * tfidf;
    dot += tfidf * weights[1];
  }
  return sigmoid(model.intercept + (squares ? dot / Math.sqrt(squares) : 0));
}

function marker(id, title, description, severity, category) {
  return { id, title, description, severity, category };
}

function observation(probability, model) {
  return { model, phishing_probability: probability, status: probability > .5 ? 'flagged' : 'not_flagged',
    prediction: probability > .5 ? 'phishing' : 'legitimate' };
}

function assess(markers, confirmed, enough, probability, weight, linkProbability = 0, url = false) {
  const groups = new Map();
  const ambiguousEntry = markers.some(m => m.id === 'credential_entry');
  for (const item of markers) {
    if (item.id === 'credential_entry') continue;
    const strength = item.id === 'insecure_http' ? .06 : {low: .06, medium: .27, high: .91}[item.severity];
    const group = ['body','subject'].includes(item.category) && ['pressure','security_notice_subject'].includes(item.id)
      ? 'security_event' : item.category;
    groups.set(group, Math.max(strength, groups.get(group) || 0));
  }
  let evidence = 1 - [...groups.values()].reduce((left, v) => left * (1 - v), 1);
  if (confirmed) evidence = Math.max(.91, evidence);
  const learned = Math.max(probability, .55 * linkProbability);
  let risk = enough || confirmed ? round1(100 * (evidence + (1 - evidence) * weight * learned)) : null;
  let level = 'safe', label = 'No clear phishing indicators detected';
  let explanation = 'The score summarizes the available signals. Verify unexpected requests independently.';
  if (confirmed || (risk !== null && evidence >= .27 && risk >= 58)) {
    level = 'danger'; label = 'Suspicious'; explanation = 'Verify this request through a separate trusted channel.';
  } else if (risk !== null && ((evidence >= .27 && risk >= 40) || (url && probability > .5))) {
    level = 'suspicious'; label = 'Caution advised'; explanation = 'The available model and structural signals warrant a closer look.';
  } else if (risk === null || ambiguousEntry) {
    risk = null;
    level = 'unknown'; label = 'Insufficient information'; explanation = ambiguousEntry
      ? 'The message mentions entering a credential. Open the service independently to verify the destination.'
      : 'The message lacks enough context for a screening score.';
  }
  if (!markers.length || level === 'unknown' || level === 'safe') {
    markers.unshift(marker('assessment_summary', label, explanation, 'low', 'assessment'));
  }
  return {score_kind: 'screening_index', risk_level: level, assessment: label, explanation, markers, risk_score: risk,
    safety_score: risk === null ? null : round1(100 - risk), ml_evaluated: true, inference_source: 'packaged_model'};
}

export function createScanner(config, suffixText) {
  if (config.version !== 1 || Object.keys(config.email.terms).length !== 20000 ||
      !config.url.trees.length || !suffixText.includes('BEGIN PRIVATE DOMAINS')) throw Error('Incomplete local model.');
  if (!Number.isFinite(config.email.intercept) || !Number.isFinite(config.url.intercept) ||
      !Object.values(config.email.terms).every(v => Array.isArray(v) && v.length === 2 && v.every(Number.isFinite)) ||
      !config.url.trees.every(tree => tree.length && tree.every((node, i) =>
        (node.length === 1 && Number.isFinite(node[0])) ||
        (node.length === 4 && Number.isInteger(node[0]) && node[0] >= 0 && node[0] < config.url.columns.length &&
         Number.isFinite(node[1]) && node.slice(2).every(j => Number.isInteger(j) && j > i && j < tree.length))))) {
    throw Error('Invalid local model parameters.');
  }
  const suffixes = new Set(suffixText.split(/\r?\n/).filter(s => s && !s.startsWith('//')).map(s => {
    const prefix = s.startsWith('*.') ? '*.' : s.startsWith('!') ? '!' : '';
    const domain = s.slice(prefix.length);
    return prefix + (/[^\x00-\x7f]/.test(domain) ? new URL('https://' + domain).hostname : domain);
  }));
  function domainParts(host) {
    const parts = host.split('.');
    for (let i = 0; i < parts.length; i++) {
      const suffix = parts.slice(i).join('.');
      const wildcard = i + 1 < parts.length && suffixes.has('*.' + parts.slice(i + 1).join('.'));
      if (suffixes.has('!' + suffix)) return {reg: suffix, label: parts[i], depth: i};
      if (suffixes.has(suffix) || wildcard) return {reg: parts.slice(Math.max(i - 1, 0)).join('.'), label: parts[i - 1] || '', depth: Math.max(i - 1, 0)};
    }
    return {reg: host, label: parts.at(-1), depth: parts.length - 1};
  }
  const patterns = Object.fromEntries(Object.entries(config.patterns).map(([k, v]) => [k, new RegExp(v, 'i')]));
  const brands = Object.entries(config.brands);
  const skeletonMap = Object.fromEntries([...('0135аекморстхуі')].map((s, i) => [s, 'olesaekmopctxyi'[i]]));
  function lookalike(label) {
    const simple = [...label.normalize('NFKC').toLowerCase()].map(c => skeletonMap[c] || c).join('');
    return simple !== label && brands.some(([name]) => name.toLowerCase() === simple);
  }
  function urlDetails(value, assume = false) {
    if (typeof value !== 'string' || value.length > 2083) throw Error('Invalid URL.');
    value = value.trim();
    if (/[\s\\\x00-\x1f]/.test(value)) throw Error('Invalid URL.');
    if (assume && !value.includes('://')) value = 'https://' + value;
    const u = new URL(value);
    if (!/^https?:$/.test(u.protocol)) throw Error('Invalid URL.');
    const host = u.hostname.replace(/^\[|\]$|\.$/g, '');
    if (!host.includes(':') && !host.split('.').every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s))) throw Error('Invalid host.');
    const isIP = host.includes(':') || /^\d+(\.\d+){3}$/.test(host);
    const {reg, depth, label} = domainParts(host);
    const rawPath = value.match(/^https?:\/\/[^/?#]*(\/[^?#]*)?/i)?.[1] || '';
    const path = rawPath === '/' ? '' : rawPath;
    const base = u.protocol + '//' + host + path;
    const fs = {URLLength: size(base), DomainLength: size(host), IsDomainIP: +isIP, NoOfSubDomain: Math.max(0, host.split('.').length - 2),
      NoOfLettersInURL: (base.match(/\p{L}/gu) || []).length, NoOfDegitsInURL: (base.match(/\p{Nd}/gu) || []).length,
      IsHTTPS: +(u.protocol === 'https:'), path_length: size(path), path_segments: path.split('/').filter(Boolean).length,
      hyphens_in_hostname: (host.match(/-/g) || []).length, internationalized: +host.split('.').some(s => s.startsWith('xn--')),
      percent_encoded_path: (path.match(/%/g) || []).length};
    const vector = config.url.columns.map(c => fs[c]);
    let logit = config.url.intercept;
    for (const tree of config.url.trees) {
      let node = tree[0];
      while (node.length > 1) node = tree[vector[node[0]] <= node[1] ? node[2] : node[3]];
      logit += node[0];
    }
    const prob = sigmoid(logit);
    const markers = [];
    function add(id, title, category = 'destination', severity = 'medium') {
      markers.push(marker(id, title, title + '. Inspect the destination independently.', severity, category));
    }
    if (!fs.IsHTTPS) add('insecure_http', 'Unencrypted HTTP', 'transport');
    if (isIP) add('raw_ip_domain', 'IP address destination');
    const hidden = /^https?:\/\/[^/?#]*@/i.test(value);
    if (hidden) add('embedded_userinfo', 'User information before hostname', 'destination', 'high');
    if (config.shorteners.includes(host)) add('shortener', 'Shortened link');
    if (fs.internationalized) add('internationalized_domain', 'Internationalized domain');
    if (lookalike(label)) add('lookalike_domain', 'Possible brand lookalike');
    if ([...u.searchParams.keys()].some(k => /^(redirect|redirect_uri|return_url|returnto|continue|target|dest|url)$/i.test(k))) add('destination_parameter', 'Destination parameter', 'structure');
    let decoded = path;
    try { decoded = decodeURIComponent(path); } catch { /* Keep literal malformed escapes. */ }
    if (size(decoded) > 100 || fs.percent_encoded_path > 6) add('complex_path', 'Complex URL path', 'structure', 'low');
    if (!isIP && depth >= 3) add('deep_subdomains', 'Nested subdomains', 'destination', 'low');
    if (brands.some(([name, domain]) => host.split('.').slice(0, -2).includes(name.toLowerCase()) && reg !== domain)) add('brand_in_subdomain', 'Brand wording in a subdomain');
    return {hostname: host, registrable_domain: reg, url: u.origin + (rawPath || '/'), hidden, markers, model_observation: observation(prob, 'url-context-v1')};
  }
  function scanUrl(url) {
    const link = urlDetails(url.trim(), true);
    return {...link, ...assess(link.markers, link.hidden, true, link.model_observation.phishing_probability, .70, 0, true)};
  }
  function scanEmail({text = '', subject = '', sender = '', reply_to = '', links = []}) {
    const prose = text.replace(/^[ \t]*>[^\n]+/gm, '');
    const markers = [];
    function add(id, title, category, severity = 'medium') {
      markers.push(marker(id, title, title + '. Check the request independently.', severity, category));
    }
    function requested(section, regex) {
      for (const m of section.matchAll(new RegExp(regex.source, 'gi'))) {
        if (!patterns.NEGATION.test(section.slice(Math.max(0, m.index - 55), m.index))) return true;
      }
      return false;
    }
    let cred = '', entry = '';
    for (const [section, category] of [[prose, 'body'], [subject, 'subject']]) {
      const matches = [...section.matchAll(new RegExp(patterns.CREDENTIAL_REQUEST.source, 'gi'))];
      for (const m of section.matchAll(new RegExp(patterns.CODE_REFERENCE.source, 'gi'))) {
        if (patterns.CODE_CONTEXT.test(section.slice(Math.max(0, m.index - 220), m.index))) matches.push(m);
      }
      for (const m of matches) {
        const before = section.slice(Math.max(0, m.index - 100), m.index);
        if (patterns.ADVICE.test(before) || patterns.ISSUING.test(before)) continue;
        const after = section.slice(m.index + m[0].length, m.index + m[0].length + 150);
        if (patterns.DISCLOSE.test(m[0]) || patterns.DELIVERY.test(after)) cred ||= category;
        else if (!patterns.OWN_SESSION.test(after)) entry ||= category;
      }
    }
    if (cred) add('credential_request', 'Direct request for sensitive information', cred, 'high');
    else if (entry) add('credential_entry', 'Credential entry context unknown', entry, 'low');
    const pressure = patterns.PRESSURE.test(subject) ? 'subject' : patterns.PRESSURE.test(prose) && 'body';
    if (pressure) add('pressure', 'Pressure or account restriction claim', pressure);
    const payment = requested(prose, patterns.PAYMENT) ? 'body' : requested(subject, patterns.PAYMENT) && 'subject';
    if (payment) add('payment_request', 'Request to transfer value', payment);
    if (/\b(prize|reward|winner|won)\b/i.test(subject)) add('reward_subject', 'Reward claim in subject', 'subject', 'low');
    if (/^\s*(re|fwd?)\s*:/i.test(subject)) add('thread_prefix', 'Reply or forward prefix', 'subject', 'low');
    if (/[A-Z]{4,}\s+[A-Z]{4,}\s+[A-Z]{4,}/.test(subject)) add('capitalized_subject', 'Capitalized subject', 'subject', 'low');
    if (patterns.SECURITY_NOTICE.test(subject)) add('security_notice_subject', 'Security notice in subject', 'subject', 'low');
    if (patterns.VERIFY.test(subject) && prose && !patterns.ACTION.test(prose)) add('subject_body_gap', 'Verification claim in subject only', 'subject', 'low');
    const addressDomain = s => ((s.match(/<([^<>]+)>/)?.[1] ?? s).match(/@([^\s<>,;]+)/)?.[1] || '').toLowerCase().replace(/\.$/, '');
    const domain = addressDomain(sender), replyDomain = addressDomain(reply_to);
    if (domain && replyDomain && domainParts(domain).reg !== domainParts(replyDomain).reg) add('reply_domain_mismatch', 'Different Reply-To domain', 'sender');
    if (domain && lookalike(domainParts(domain).label)) add('sender_lookalike', 'Possible sender-domain lookalike', 'sender');
    const name = sender.includes('<') ? sender.split('<')[0].trim().replace(/^"|"$/g, '') : '';
    if (domain && brands.some(([b, d]) => new RegExp('^' + b + '( (support|security|team))?$', 'i').test(name) && domainParts(domain).reg !== d)) add('display_name_domain_mismatch', 'Display name and sender domain differ', 'sender');
    const mismatch = markers.some(m => m.category === 'sender');
    const found = new Map();
    let limited = false;
    for (const item of [...links, ...(subject.match(webLink) || []).map(trimLink), ...(text.match(webLink) || []).map(trimLink)]) {
      const value = typeof item === 'string' ? item : item?.url;
      try {
        const key = new URL(value).href;
        if (!found.has(key) && found.size >= 40) { limited = true; continue; }
        const link = found.get(key) || urlDetails(value);
        found.set(key, link);
        const label = typeof item === 'object' && item?.label;
        const shown = label && (label.match(webLink)?.[0] || label.trim().match(/^(?:[\w-]+\.)+[a-z]{2,}(?:\/\S*)?$/i)?.[0]);
        if (shown && urlDetails(trimLink(shown), true).registrable_domain !== link.registrable_domain && !link.labelMismatch) {
          link.markers.push(marker('destination_label_mismatch', 'Visible and actual hosts differ', 'Visible link text names a different destination.', 'high', 'link'));
          link.labelMismatch = true;
        }
      } catch { /* Unsupported or malformed destination. Never visit it. */ }
    }
    const items = [...found.values()];
    for (const link of items) {
      link.sender_domain_relation = !domain ? 'unknown' : domainParts(domain).reg === link.registrable_domain ? 'same' : 'different';
    }
    const deceptive = items.some(l => l.hidden || l.labelMismatch);
    if (deceptive) add('link_deception', 'Deceptive destination structure', 'link', 'high');
    const warning = items.some(l => l.markers.some(m => ['lookalike_domain','brand_in_subdomain','raw_ip_domain','shortener'].includes(m.id)));
    const confirmed = cred || deceptive || (entry && (warning || (mismatch && items.some(l => l.sender_domain_relation === 'different')))) || (pressure && payment) || (payment && mismatch) || (items.length && requested(prose, patterns.VERIFY) && (warning || mismatch));
    const variety = new Set((prose.toLowerCase().match(words) || []).filter(t => /^\p{L}{3,}$/u.test(t))).size;
    const enough = markers.length || items.length || (variety >= 7 && (domain || subject || /[.!?]\s+[\p{L}\p{N}_]/u.test(prose)));
    const prob = emailProbability(text, config.email);
    const result = assess(markers, confirmed, enough, prob, .25, Math.max(0, ...items.map(l => l.model_observation.phishing_probability)));
    if (result.safety_score !== null) {
      result.markers.push(marker('score_meaning', 'About this score',
        'This screening index combines model output and observed signals. The probability that this message is safe is unknown.', 'low', 'assessment'));
    }
    result.markers.push(marker('standalone_analysis', 'On-device analysis', 'Packaged email and link models ran locally. History, privacy checks and live reputation are unavailable in this mode.', 'low', 'availability'));
    return {...result, model_observation: observation(prob, 'email-tfidf-v1'), links: items, links_limited: limited,
      sender: {domain, reply_to_domain: replyDomain, authentication: 'unavailable'}, persistence: {history: 'unavailable'}};
  }
  return {scanEmail, scanUrl};
}
