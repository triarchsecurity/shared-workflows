import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';
import { loadCtx, report } from '../check-all.mjs';
import { check } from '../checks/apphosting-secrets.mjs';

test('CONF-03: clean-atlas — every apphosting secret is provisioned => 0 findings', () => {
  const findings = check(loadCtx(fixture('clean-atlas')));
  assert.equal(findings.length, 0);
});

test('CONF-03: dirty-unprovisioned-apphosting — unprovisioned binding flagged', () => {
  const findings = check(loadCtx(fixture('dirty-unprovisioned-apphosting')));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].req, 'CONF-03');
  assert.match(findings[0].message, /UNPROVISIONED_SECRET/);
  assert.match(findings[0].message, /triarchsecurity-atlas/);
});

test('CONF-03: a yaml whose project has no manifest is skipped (unreachable customer project)', () => {
  const ctx = {
    baseline: {},
    manifests: {
      apphostingProjects: {}, // no mapping for this file
      projectSecrets: {},
      apphostingFiles: [{ name: 'apphosting.revolutioncyber.yaml', text: 'env:\n  - variable: X\n    secret: SOME_SECRET' }],
    },
  };
  assert.equal(check(ctx).length, 0, 'no project mapping => skip, do not hard-fail');
});

test('CONF-03: warn-first dual mode on the dirty fixture', () => {
  const findings = check(loadCtx(fixture('dirty-unprovisioned-apphosting')));
  const warn = report(findings, { enforce: false });
  assert.equal(warn.exitCode, 0);
  assert.ok(warn.annotations.some((l) => l.startsWith('::warning::')));

  const err = report(findings, { enforce: true });
  assert.equal(err.exitCode, 1);
  assert.ok(err.annotations.some((l) => l.startsWith('::error::')));
});
