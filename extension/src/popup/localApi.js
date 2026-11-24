export function localApi(base, path, options) {
  const address = new URL(base);
  if (address.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(address.hostname) ||
      address.username || address.password) {
    throw new Error('Enter a local SentinelAI server address.');
  }
  return fetch(address.origin + path, { ...options, redirect: 'error' });
}

export async function requestLocal(base, path, data) {
  const options = data === undefined ? undefined : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  };
  const response = await localApi(base, path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Local analysis failed.');
  return result;
}
