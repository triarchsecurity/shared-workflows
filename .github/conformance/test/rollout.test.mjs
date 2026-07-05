import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Rollout / no-red-fleet guarantee: drive the REAL check-all.mjs process (not
// just the exported functions) against a known-dirty fixture and assert the
// warn-first exit contract on the actual process exit code.

const CONF_DIR = fileURLToPath(new URL('..', import.meta.url));
const CHECK_ALL = join(CONF_DIR, 'check-all.mjs');
const DIRTY_TARGET = join(CONF_DIR, 'test', 'fixtures', 'dirty-five-missing-grants');

function run(enforce) {
  try {
    const stdout = execFileSync('node', [CHECK_ALL, '--target', DIRTY_TARGET], {
      env: { ...process.env, ENFORCE: String(enforce), GITHUB_STEP_SUMMARY: '' },
      encoding: 'utf8',
    });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status, stdout: e.stdout ? e.stdout.toString() : '' };
  }
}

test('rollout: ENFORCE=false => exit 0 and a ::warning:: line (no-red-fleet)', () => {
  const { code, stdout } = run(false);
  assert.equal(code, 0);
  assert.match(stdout, /::warning::/);
});

test('rollout: ENFORCE=true => exit 1 and a ::error:: line', () => {
  const { code, stdout } = run(true);
  assert.equal(code, 1);
  assert.match(stdout, /::error::/);
});
