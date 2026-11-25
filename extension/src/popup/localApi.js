// Scan requests carry private draft text. Keep every request on loopback.
export async function localApi(base, path, options = {}) {
  const target = new URL(base);
  if (target.protocol !== 'http:' ||
      !['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname) ||
      target.username || target.password || target.pathname !== '/' ||
      target.search || target.hash) {
    throw new Error('Enter a local HTTP backend address.');
  }
  const timeout = AbortSignal.timeout(8000);
  return fetch(target.origin + path, {
    ...options,
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: options.signal ? AbortSignal.any([options.signal, timeout]) : timeout,
  });
}
