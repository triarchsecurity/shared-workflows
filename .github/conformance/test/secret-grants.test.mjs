import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';
import { loadCtx, report } from '../check-all.mjs';
import { check } from '../checks/secret-grants.mjs';

test('CONF-01: clean-atlas — every --secret ref is in the grants manifest => 0 findings', () => {
  const findings = check(loadCtx(fixture('clean-atlas')));
  assert.equal(findings.length, 0);
});

test('CONF-01: dirty-five-missing-grants — ungranted secret flagged with remediation', () => {
  const findings = check(loadCtx(fixture('dirty-five-missing-grants')));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].req, 'CONF-01');
  assert.match(findings[0].message, /NEW_UNGRANTED_SECRET/);
  assert.match(findings[0].message, /triarchsecurity-atlas/);
  assert.match(findings[0].remediation, /secretAccessor/);
  assert.match(findings[0].remediation, /ci-secret-grants\.json/);
});

test('CONF-01: resolves simple PROJECT= var assignments (--project=$PROJECT)', () => {
  const base = {
    baseline: {},
    workflows: [{
      name: 'foundry-eval.yml',
      text: [
        'run: |',
        '  PROJECT=triarchsecurity-atlas',
        '  X="$(gcloud secrets versions access latest --secret=SESSION_SECRET_DEV --project=$PROJECT)"',
      ].join('\n'),
    }],
  };
  const covered = check({ ...base, manifests: { ciSecretGrants: [{ secret: 'SESSION_SECRET_DEV', project: 'triarchsecurity-atlas' }] } });
  assert.equal(covered.length, 0, 'resolved (secret,project) is covered => no finding');

  const uncovered = check({ ...base, manifests: { ciSecretGrants: [] } });
  assert.equal(uncovered.length, 1, 'resolved but ungranted => one finding');
  assert.match(uncovered[0].message, /SESSION_SECRET_DEV/);
});

test('CONF-01: warn-first dual mode on the dirty fixture', () => {
  const findings = check(loadCtx(fixture('dirty-five-missing-grants')));
  const warn = report(findings, { enforce: false });
  assert.equal(warn.exitCode, 0);
  assert.ok(warn.annotations.some((l) => l.startsWith('::warning::')), 'ENFORCE=false emits ::warning::');

  const err = report(findings, { enforce: true });
  assert.equal(err.exitCode, 1);
  assert.ok(err.annotations.some((l) => l.startsWith('::error::')), 'ENFORCE=true emits ::error::');
});
