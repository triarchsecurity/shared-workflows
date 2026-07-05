import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';
import { loadCtx, report } from '../check-all.mjs';
import { check } from '../checks/thin-caller.mjs';

test('CONF-04: clean-portal — golden thin-caller => 0 findings', () => {
  const findings = check(loadCtx(fixture('clean-portal')));
  assert.equal(findings.length, 0);
});

test('CONF-04: clean-atlas — 0 hard findings, trigger-set gap is SOFT only', () => {
  const findings = check(loadCtx(fixture('clean-atlas')));
  const hard = findings.filter((f) => !f.soft);
  const soft = findings.filter((f) => f.soft);
  assert.equal(hard.length, 0, 'canonical shape => no hard findings');
  assert.ok(soft.length >= 1, 'missing release/**+hotfix/** triggers => advisory soft finding');
  assert.equal(soft[0].req, 'CONF-04');
});

test('CONF-04: dirty-thin-caller-drift — 2nd job + inline run + @release/v8 all flagged', () => {
  const findings = check(loadCtx(fixture('dirty-thin-caller-drift')));
  const hard = findings.filter((f) => !f.soft);
  assert.ok(hard.length >= 3, `expected >=3 hard findings, got ${hard.length}`);
  const joined = hard.map((f) => f.message).join(' | ');
  assert.match(joined, /job/i, 'flags the extra job');
  assert.match(joined, /release\/v9/, 'flags the wrong ref');
  assert.match(joined, /inline|run|steps/i, 'flags the inline run/steps');
  for (const f of hard) assert.equal(f.req, 'CONF-04');
});

test('CONF-04: warn-first dual mode on the dirty fixture', () => {
  const findings = check(loadCtx(fixture('dirty-thin-caller-drift')));
  const warn = report(findings, { enforce: false });
  assert.equal(warn.exitCode, 0);
  assert.ok(warn.annotations.some((l) => l.startsWith('::warning::')));

  const err = report(findings, { enforce: true });
  assert.equal(err.exitCode, 1);
  assert.ok(err.annotations.some((l) => l.startsWith('::error::')));
});
