import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Tests the REAL semver_cmp + INV-3 verdict logic from gate-prod-version.yml — not a
// re-implementation. We extract the bash `semver_cmp() { ... }` block (matched by its
// own indentation so we never drift from the shipped source) and the INV-3 `-le 0`
// rule, dedent, and drive them through bash. Prevents regression of the 2026-07-15
// prerelease-blind bug (2.2.0-rc.38 falsely "not higher" than 2.2.0-rc.36).

const GATE_YML = fileURLToPath(
  new URL('../../workflows/gate-prod-version.yml', import.meta.url),
);

function extractSemverCmp() {
  const src = readFileSync(GATE_YML, 'utf8');
  // Match `<indent>semver_cmp() {` ... up to the closing `<indent>}` at the same indent.
  const m = src.match(/^([ \t]*)semver_cmp\(\) \{\n[\s\S]*?\n\1\}$/m);
  assert.ok(m, 'could not locate semver_cmp() in gate-prod-version.yml');
  const indent = m[1];
  // Dedent so it is valid top-level bash.
  return m[0]
    .split('\n')
    .map((line) => (line.startsWith(indent) ? line.slice(indent.length) : line))
    .join('\n');
}

const SEMVER_CMP = extractSemverCmp();

// cmp(A, B) -> -1 | 0 | 1, running the extracted bash function.
function cmp(a, b) {
  const dir = mkdtempSync(join(tmpdir(), 'gate-semver-'));
  const script = join(dir, 'cmp.sh');
  writeFileSync(script, `${SEMVER_CMP}\nsemver_cmp "$1" "$2"\n`);
  const out = execFileSync('bash', [script, a, b], { encoding: 'utf8' }).trim();
  return Number(out);
}

// INV-3 blocks when target is NOT strictly higher than prod (cmp <= 0).
function inv3Blocks(target, prod) {
  return cmp(target, prod) <= 0;
}

test('semver_cmp: rc.38 > rc.36 (the live regression)', () => {
  assert.equal(cmp('2.2.0-rc.38', '2.2.0-rc.36'), 1);
});

test('semver_cmp: rc.5 < rc.36 (numeric prerelease ordering, not lexical)', () => {
  assert.equal(cmp('2.2.0-rc.5', '2.2.0-rc.36'), -1);
});

test('semver_cmp: full ascending chain rc.5 < rc.36 < rc.38', () => {
  assert.equal(cmp('2.2.0-rc.5', '2.2.0-rc.36'), -1);
  assert.equal(cmp('2.2.0-rc.36', '2.2.0-rc.38'), -1);
});

test('semver_cmp: final release outranks its prerelease (2.2.0 > 2.2.0-rc.38)', () => {
  assert.equal(cmp('2.2.0', '2.2.0-rc.38'), 1);
  assert.equal(cmp('2.2.0-rc.38', '2.2.0'), -1);
});

test('semver_cmp: higher minor wins (2.3.0 > 2.2.0)', () => {
  assert.equal(cmp('2.3.0', '2.2.0'), 1);
});

test('semver_cmp: equal versions compare 0', () => {
  assert.equal(cmp('2.2.0-rc.38', '2.2.0-rc.38'), 0);
  assert.equal(cmp('2.2.0', '2.2.0'), 0);
});

test('INV-3: allows the legitimate rc.36 -> rc.38 prod promotion', () => {
  assert.equal(inv3Blocks('2.2.0-rc.38', '2.2.0-rc.36'), false);
});

test('INV-3: still blocks a genuine backward roll (rc.36 vs prod rc.38)', () => {
  assert.equal(inv3Blocks('2.2.0-rc.36', '2.2.0-rc.38'), true);
});

test('INV-3: still blocks a same-version re-deploy (equal -> not higher)', () => {
  assert.equal(inv3Blocks('2.2.0-rc.38', '2.2.0-rc.38'), true);
  assert.equal(inv3Blocks('2.2.0', '2.2.0'), true);
});

test('INV-3: allows promoting the final over its prerelease (2.2.0 over rc.38)', () => {
  assert.equal(inv3Blocks('2.2.0', '2.2.0-rc.38'), false);
});
