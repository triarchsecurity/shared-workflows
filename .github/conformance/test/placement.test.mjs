import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// CONF-05: the checker code is single-homed under shared-workflows'
// .github/conformance/. No consumer/fixture tree may copy check-all.mjs or a
// checks/*.mjs, and no consumer ci-cd.yml may own a local `conformance:` job.
// Guards against the retired per-repo D-1 pattern AR#5 rule 2 forbids.

const CONF_DIR = fileURLToPath(new URL('..', import.meta.url));
const FIXTURES = join(CONF_DIR, 'test', 'fixtures');

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git') continue;
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

test('CONF-05: check-all.mjs is single-homed (exactly one, under .github/conformance/)', () => {
  const copies = walk(CONF_DIR)
    .filter((p) => !p.includes(`${join(CONF_DIR, 'node_modules')}`))
    .filter((p) => p.endsWith('check-all.mjs'));
  assert.equal(copies.length, 1, `expected one check-all.mjs, found: ${copies.join(', ')}`);
  assert.equal(copies[0], join(CONF_DIR, 'check-all.mjs'));
});

test('CONF-05: no fixture consumer tree copies a checker module', () => {
  const checkerCopies = walk(FIXTURES).filter((p) =>
    /(check-all\.mjs|[\\/]checks[\\/][a-z-]+\.mjs)$/.test(p),
  );
  assert.deepEqual(checkerCopies, [], 'a consumer repo must reference the shared checker, never own it');
});

test('CONF-05: no fixture ci-cd.yml defines a local conformance job', () => {
  const callers = walk(FIXTURES).filter((p) => p.endsWith('ci-cd.yml'));
  assert.ok(callers.length > 0, 'expected fixture ci-cd.yml files to scan');
  for (const p of callers) {
    const text = readFileSync(p, 'utf8');
    assert.doesNotMatch(text, /^\s{2}conformance:\s*$/m, `${p} must not own a conformance job`);
  }
});
