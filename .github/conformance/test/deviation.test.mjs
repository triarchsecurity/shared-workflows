import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';
import { loadCtx, report } from '../check-all.mjs';
import { check } from '../checks/deviation.mjs';

test('CONF-02: clean-atlas — WIF + deploy-customer exemptioned => 0 findings', () => {
  const findings = check(loadCtx(fixture('clean-atlas')));
  assert.equal(findings.length, 0);
});

test('CONF-02: dirty-rogue-scan — bespoke security-scan.yml with no exemption flagged', () => {
  const findings = check(loadCtx(fixture('dirty-rogue-scan')));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].req, 'CONF-02');
  assert.match(findings[0].message, /security-scan\.yml/);
  assert.match(findings[0].message, /scan/);
});

test('CONF-02: app-cron and structural-guard need NO exemption (Pitfall 2)', () => {
  const baseline = {
    portal_sanctioned: ['ci-cd.yml'],
    admin_sanctioned: ['ci-cd.yml'],
    allowed_classes: ['app-cron', 'structural-guard'],
    regulated_classes: ['gate', 'scan', 'pat', 'wif', 'secret-source'],
  };
  const ctx = {
    baseline,
    manifests: { exemptions: [] },
    workflows: [
      { name: 'mercury-cron.yml', text: 'on:\n  schedule:\n    - cron: "0 6 * * *"\njobs:\n  run:\n    runs-on: ubuntu-latest' },
      { name: 'observability-guards.yml', text: 'name: Observability Guards\non: pull_request\njobs:\n  guard:\n    runs-on: ubuntu-latest' },
    ],
  };
  assert.equal(check(ctx).length, 0, 'app-cron + structural-guard classes are allowed everywhere');
});

test('CONF-02: an unexemptioned WIF workflow is flagged', () => {
  const baseline = {
    portal_sanctioned: ['ci-cd.yml'],
    admin_sanctioned: ['ci-cd.yml'],
    allowed_classes: ['app-cron', 'structural-guard'],
    regulated_classes: ['gate', 'scan', 'pat', 'wif', 'secret-source'],
  };
  const ctx = {
    baseline,
    manifests: { exemptions: [] },
    workflows: [
      { name: 'migrate.yml', text: 'jobs:\n  m:\n    steps:\n      - with:\n          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}' },
    ],
  };
  const findings = check(ctx);
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /migrate\.yml/);
  assert.match(findings[0].message, /wif/);
});

test('CONF-02: warn-first dual mode on the dirty fixture', () => {
  const findings = check(loadCtx(fixture('dirty-rogue-scan')));
  const warn = report(findings, { enforce: false });
  assert.equal(warn.exitCode, 0);
  assert.ok(warn.annotations.some((l) => l.startsWith('::warning::')));

  const err = report(findings, { enforce: true });
  assert.equal(err.exitCode, 1);
  assert.ok(err.annotations.some((l) => l.startsWith('::error::')));
});
