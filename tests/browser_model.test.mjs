import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import test from 'node:test';
import {createScanner} from '../extension/src/inference/screening.mjs';

const dir = new URL('../extension/public/models/', import.meta.url);
const weights = JSON.parse(await readFile(new URL('screening.json', dir)));
const psl = await readFile(new URL('public_suffix_list.dat', dir), 'utf8');
const scanner = createScanner(weights, psl);

test('packaged weights and abstention are independent of Python', () => {
  const a = scanner.scanEmail({text: 'Hello'});
  assert.equal(a.assessment, 'Insufficient information');
  assert.equal(a.safety_score, null);
  assert.ok(Math.abs(a.model_observation.phishing_probability - .8870) < .0001);
});

test('header comparison uses the address, including a quoted display name', () => {
  const a = scanner.scanEmail({text: 'See you at the library.', sender: 'Team <abc@example.org>',
    reply_to: '"notices@example.net" <team@example.org>'});
  assert.ok(!a.markers.some(m => m.id === 'reply_domain_mismatch'));
});

test('package error is visible before any numerical scoring', () => {
  assert.throws(() => createScanner({...weights, email: {...weights.email, intercept: null}}, psl));
  assert.throws(() => createScanner(weights, 'incomplete list'));
});

test('multiple links, public suffix boundaries, and stripped query values', () => {
  const r = scanner.scanEmail({text: 'Here are the resources discussed in class.',
    links: [{url: 'https://one.github.io/doc?a=private-example', label: 'https://two.github.io/doc'},
      {url: 'https://example.org/read'}]});
  assert.equal(r.links.length, 2);
  assert.equal(r.assessment, 'Suspicious');
  assert.ok(!JSON.stringify(r).includes('private-example'));
});

test('context distinguishes delivery, entry, advice and disclosure', async () => {
  const cases = JSON.parse(await readFile(new URL('./fixtures/credential_context.json', import.meta.url)));
  for (const c of cases) {
    const r = scanner.scanEmail(c);
    assert.equal(r.risk_level, c.expected, c.case);
    assert.equal(r.score_kind, 'screening_index');
    assert.equal(r.sender.authentication, 'unavailable');
    if (c.marker) assert.ok(r.markers.some(m => m.id === c.marker), c.case);
    if (c.expected !== 'danger') assert.ok(!r.markers.some(m => m.id === 'credential_request'), c.case);
    if (c.expected === 'unknown') assert.equal(r.safety_score, null);
  }
});

test('incidental outer whitespace preserves the destination for email inference', () => {
  const input = {text: 'Here is the reading list for class.', sender: 'class@example.org'};
  const clean = scanner.scanEmail({...input, links: ['http://example.org/read']});
  const wrapped = scanner.scanEmail({...input, links: ['\nhttp://example.org/read \t']});
  assert.deepEqual(wrapped.links, clean.links);
  assert.equal(wrapped.links[0].sender_domain_relation, 'same');
  assert.equal(wrapped.risk_score, clean.risk_score);
});
