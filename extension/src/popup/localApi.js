// Scan requests carry private draft text. Keep every request on loopback.
export function localOrigin(base) {
  const target = new URL(base);
  if (target.protocol !== 'http:' ||
      !['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname) ||
      target.username || target.password || target.pathname !== '/' ||
      target.search || target.hash) {
    throw new Error('Enter a local HTTP backend address.');
  }
  return target.origin;
}

export async function localApi(base, path, options = {}) {
  const origin = localOrigin(base);
  if (globalThis.chrome?.runtime?.id && globalThis.location?.protocol === 'chrome-extension:' &&
      typeof document !== 'undefined' && options.method === 'POST' && ['/api/scan-url', '/api/scan-email'].includes(path)) {
    const data = await chrome.runtime.sendMessage({type: 'SCREEN', kind: path.slice('/api/scan-'.length),
      origin, input: JSON.parse(options.body)});
    if (!data) throw Error('The extension scanner could not be reached.');
    return Response.json(data);
  }
  const timeout = AbortSignal.timeout(8000);
  return fetch(origin + path, {
    ...options,
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: options.signal ? AbortSignal.any([options.signal, timeout]) : timeout,
  });
}
