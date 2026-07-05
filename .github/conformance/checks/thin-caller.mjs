// CONF-04 — ci-cd.yml thin-caller shape drift (AR#5 rule 2 mechanized).
//
// Parse ci-cd.yml and assert the canonical thin-caller shape:
//   1. exactly one job
//   2. the caller job pins ci-cd.yml@release/v9 (the moving canonical ref)
//   3. no inline steps:/run: in the caller (no bespoke logic)
//   4. secrets: inherit present
//   5. with: keys are a subset of the canonical input set
// A trigger-branch-set mismatch (atlas omits release/**+hotfix/**) is a SOFT
// (advisory) finding only — never a hard fail.
//
// NOTE: js-yaml (YAML 1.1) coerces the `on:` key to boolean `true`. We read both
// `doc.on` and `doc[true]` to survive that GitHub-Actions gotcha.

import yaml from 'js-yaml';

const CANONICAL_TRIGGERS = ['main', 'dev', 'release/**', 'hotfix/**'];

function pushBranches(doc) {
  const on = (doc && (doc.on ?? doc[true])) || {};
  const push = on.push || {};
  const branches = push.branches || [];
  return Array.isArray(branches) ? branches.map(String) : [];
}

export function check(ctx) {
  const findings = [];
  const wf = (ctx.workflows || []).find((w) => w.name === 'ci-cd.yml');
  if (!wf) return findings; // no caller present to check

  const b = ctx.baseline || {};
  const canonicalRef = b.canonical_ref || 'ci-cd.yml@release/v9';
  const canonicalInputs = new Set(b.canonical_inputs || []);

  let doc;
  try {
    doc = yaml.load(wf.text);
  } catch (e) {
    findings.push({
      req: 'CONF-04',
      message: `ci-cd.yml is not valid YAML: ${e.message}`,
      remediation: 'Fix the YAML syntax in the thin caller.',
    });
    return findings;
  }

  const jobs = (doc && doc.jobs) || {};
  const jobNames = Object.keys(jobs);

  // 1. exactly one job.
  if (jobNames.length !== 1) {
    findings.push({
      req: 'CONF-04',
      message: `ci-cd.yml must define exactly one job (the thin caller); found ${jobNames.length} job(s): [${jobNames.join(', ')}]`,
      remediation: 'Remove bespoke jobs; all pipeline logic lives centrally in shared-workflows.',
    });
  }

  for (const [jobName, rawJob] of Object.entries(jobs)) {
    const job = rawJob || {};
    if (job.uses) {
      // 2. canonical ref.
      if (!String(job.uses).endsWith(canonicalRef)) {
        findings.push({
          req: 'CONF-04',
          message: `ci-cd.yml job '${jobName}' must pin ${canonicalRef}; found '${job.uses}'`,
          remediation: `Repoint the caller's uses: to …/${canonicalRef}`,
        });
      }
      // 4. secrets: inherit.
      if (job.secrets !== 'inherit') {
        findings.push({
          req: 'CONF-04',
          message: `ci-cd.yml job '${jobName}' must set 'secrets: inherit'`,
          remediation: 'Add secrets: inherit to the caller job.',
        });
      }
      // 5. with: keys subset of the canonical input set.
      const unknown = Object.keys(job.with || {}).filter((k) => !canonicalInputs.has(k));
      if (unknown.length) {
        findings.push({
          req: 'CONF-04',
          message: `ci-cd.yml job '${jobName}' passes non-canonical input(s) [${unknown.join(', ')}]`,
          remediation: 'Remove with: keys outside the canonical ci-cd.yml input set.',
        });
      }
      // 3. no inline steps/run in the caller job.
      if (job.steps || job.run) {
        findings.push({
          req: 'CONF-04',
          message: `ci-cd.yml caller job '${jobName}' has inline steps:/run: — thin callers carry no bespoke logic`,
          remediation: 'Move inline logic into shared-workflows.',
        });
      }
    } else {
      // A job without `uses:` is bespoke inline logic (the drift shape).
      findings.push({
        req: 'CONF-04',
        message: `ci-cd.yml job '${jobName}' is a bespoke job with inline steps:/run: (not a shared-workflow call)`,
        remediation: 'Remove the extra job; if it is truly shared, add it to shared-workflows.',
      });
    }
  }

  // 6. (soft) trigger-branch parity — advisory only.
  const missingTriggers = CANONICAL_TRIGGERS.filter((t) => !pushBranches(doc).includes(t));
  if (missingTriggers.length) {
    findings.push({
      req: 'CONF-04',
      soft: true,
      message: `ci-cd.yml push triggers omit [${missingTriggers.join(', ')}] vs the canonical set (advisory)`,
      remediation: 'Add the missing push branch triggers for full parity (non-blocking).',
    });
  }

  return findings;
}
