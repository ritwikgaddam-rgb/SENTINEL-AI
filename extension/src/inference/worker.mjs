import { createScanner } from './screening.mjs';
import { localApi, localOrigin } from '../popup/localApi.js';

const standard = 'http://127.0.0.1:8000';
const connections = new Map();
let scannerPromise;

function packagedScanner() {
  if (!scannerPromise) {
    const read = async file => {
      const response = await fetch(chrome.runtime.getURL('models/' + file));
      if (!response.ok) throw Error('Missing packaged model.');
      return response;
    };
    const started = performance.now();
    scannerPromise = Promise.all([read('screening.json').then(r => r.json()),
      read('public_suffix_list.dat').then(r => r.text())])
      .then(([weights, suffixes]) => {
        const scanner = createScanner(weights, suffixes);
        performance.measure('sentinel-model-load', {start: started, end: performance.now()});
        return scanner;
      })
      .catch(err => { scannerPromise = undefined; throw err; });
  }
  return scannerPromise;
}

async function connected(origin) {
  const state = connections.get(origin);
  if (state?.probe) return state.probe;
  if (state && state.until > Date.now()) return state.online;
  const probe = (async () => {
    try {
      const res = await localApi(origin, '/api/health', {signal: AbortSignal.timeout(900)});
      return res.ok && (await res.json()).status === 'online';
    } catch { return false; }
  })();
  connections.set(origin, {probe});
  const online = await probe;
  connections.set(origin, {online, until: Date.now() + (online ? 30000 : 5000)});
  return online;
}

function payload(kind, data) {
  if (!data || typeof data !== 'object') throw Error('Missing scan input.');
  if (kind === 'url') {
    if (typeof data.url !== 'string' || data.url.length > 2083) throw Error('Invalid URL.');
    return {url: data.url};
  }
  const fields = {};
  for (const [key, max] of Object.entries({text: 20000, subject: 500, sender: 500, reply_to: 500})) {
    const v = data[key] ?? '';
    if (typeof v !== 'string' || v.length > max) throw Error('Invalid email field.');
    fields[key] = v;
  }
  if (!(fields.text.trim() || fields.subject.trim())) throw Error('Empty email.');
  fields.links = (Array.isArray(data.links) ? data.links : []).slice(0, 80).flatMap(item => {
    if (typeof item === 'string') return item.length <= 2083 ? [item] : [];
    if (typeof item?.url !== 'string' || item.url.length > 2083) return [];
    return [{url: item.url, label: typeof item.label === 'string' ? item.label.slice(0, 200) : ''}];
  });
  fields.labels = (Array.isArray(data.labels) ? data.labels : []).slice(0, 50)
    .filter(x => typeof x === 'string').map(x => x.slice(0, 40));
  return fields;
}

async function scan(kind, origin, input) {
  if (await connected(origin)) {
    try {
      const res = await localApi(origin, '/api/scan-' + kind, {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(input),
        signal: AbortSignal.timeout(6000)});
      if (res.ok) {
        const result = await res.json();
        if (Array.isArray(result.markers) && result.ml_evaluated === true) return {...result, inference_source: 'loopback'};
      }
    } catch { /* Recover a scan after loss of the backend. */ }
    connections.set(origin, {online: false, until: Date.now() + 5000});
  }
  const local = await packagedScanner();
  const result = kind === 'url' ? local.scanUrl(input.url) : local.scanEmail(input);
  return {...result, persistence: {...result.persistence, collection: 'unavailable'}, markers: [
    ...result.markers, {id: 'collection_unavailable', title: 'Threat collection unavailable',
      description: 'This scan ran offline. Threat collection requires the local backend.', severity: 'low'},
  ]};
}

export function handleScan(message, sender, respond) {
  const popup = sender.url === chrome.runtime.getURL('popup.html');
  const gmail = sender.tab && sender.frameId === 0 && sender.url?.startsWith('https://mail.google.com/');
  if (sender.id !== chrome.runtime.id || (!popup && !gmail) ||
      !['email', 'url'].includes(message.kind) || (gmail && message.kind !== 'email')) return false;
  (async () => {
    const origin = localOrigin(popup ? (message.origin || standard) : standard);
    const result = await scan(message.kind, origin, payload(message.kind, message.input));
    if (gmail) {
      // The content script only needs the public verdict, never the private backend payload.
      const {risk_level, risk_score, safety_score, assessment, markers, private_items_count, inference_source, persistence} = result;
      return {risk_level, risk_score, safety_score, assessment, markers: markers.map(({id, title, description, severity}) =>
        ({id, title, description, severity})), private_items_count, inference_source,
        persistence: {collection: persistence?.collection}};
    }
    return result;
  })().then(respond, () => respond({assessment: 'Analysis unavailable', risk_level: 'unknown',
    ml_evaluated: false, risk_score: null, safety_score: null, markers: [{id: 'unavailable', title: 'Analysis unavailable',
      description: 'The local scanner could not assess this input. Check the input and installed model files.', severity: 'low'}]}));
  return true;
}
