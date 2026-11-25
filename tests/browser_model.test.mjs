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
