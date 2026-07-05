// CI/infra conformance orchestrator (CONF-01..05, AR#5 rules 1 & 2 mechanized).
//
// The orchestrator is the ONLY component that touches the filesystem: it loads
// the target repo's files into a plain `ctx` object and passes it to each pure
// checker (checks/*.mjs export `check(ctx) : Finding[]`). Keeping the checkers
// fs/network-free makes them trivially fixture-testable under `node --test`.
//
// CLI:  node check-all.mjs --target <repoRoot>
//   env ENFORCE=true  => findings become ::error:: and the process exits 1 if any
//                        HARD finding is present.
//   env ENFORCE=false => every finding is a ::warning:: and the process exits 0
//                        (warn-first: this is how the assertion rolls out across
//                        the fleet without reddening 7 repos on day one).
// Soft findings (advisory, e.g. trigger-set parity) are ALWAYS ::warning:: and
// never affect the exit code, in either mode.

import { readFileSync, readdirSync, existsSync, realpathSync, appendFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

import { check as checkSecretGrants } from './checks/secret-grants.mjs';
import { check as checkDeviation } from './checks/deviation.mjs';
import { check as checkApphosting } from './checks/apphosting-secrets.mjs';
import { check as checkThinCaller } from './checks/thin-caller.mjs';

const CHECKER_DIR = dirname(fileURLToPath(import.meta.url));
const CHECKS = [checkSecretGrants, checkDeviation, checkApphosting, checkThinCaller];

function readIf(path) {
  return existsSync(path) ? readFileSync(path, 'utf8') : null;
}

function listYaml(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));
}

// Load every target file the checkers need into a single ctx object.
export function loadCtx(targetRoot) {
  const wfDir = join(targetRoot, '.github', 'workflows');
  const workflows = listYaml(wfDir).map((name) => ({
    name,
    text: readFileSync(join(wfDir, name), 'utf8'),
  }));

  // Cross-repo baseline lives beside the checker (shared-workflows), not the target.
  const baselineText = readIf(join(CHECKER_DIR, 'baseline.yaml'));
  const baseline = baselineText ? yaml.load(baselineText) : {};

  const confDir = join(targetRoot, '.conformance');

  const grantsText = readIf(join(confDir, 'ci-secret-grants.json'));
  const ciSecretGrants = grantsText ? JSON.parse(grantsText) : [];

  const exemptText = readIf(join(confDir, 'exemptions.yaml'));
  const exemptions = exemptText ? yaml.load(exemptText) || [] : [];

  const apphostingProjectsText = readIf(join(confDir, 'apphosting-projects.json'));
  const apphostingProjects = apphostingProjectsText ? JSON.parse(apphostingProjectsText) : {};

  const apphostingFiles = existsSync(targetRoot)
    ? readdirSync(targetRoot)
        .filter((f) => /^apphosting.*\.ya?ml$/.test(f))
        .map((name) => ({ name, text: readFileSync(join(targetRoot, name), 'utf8') }))
    : [];

  // Load the provisioned-secret manifest for each project the apphosting map references.
  const projectSecrets = {};
  const psDir = join(confDir, 'project-secrets');
  for (const project of new Set(Object.values(apphostingProjects))) {
    const text = readIf(join(psDir, `${project}.txt`));
    if (text !== null) {
      projectSecrets[project] = text.split('\n').map((s) => s.trim()).filter(Boolean);
    }
  }

  return {
    targetRoot,
    baseline,
    workflows,
    manifests: { ciSecretGrants, exemptions, apphostingProjects, projectSecrets, apphostingFiles },
  };
}

export function runChecks(ctx) {
  return CHECKS.flatMap((fn) => fn(ctx));
}

// Turn findings into annotation lines + a step-summary + an exit code, applying
// the warn-first ENFORCE gate. Pure — callers (main + tests) decide what to do.
export function report(findings, { enforce }) {
  const annotations = [];
  const summary = ['# CI/infra conformance', ''];

  for (const f of findings) {
    const hard = !f.soft;
    const level = hard && enforce ? 'error' : 'warning';
    const suffix = f.remediation ? ` — ${f.remediation}` : '';
    annotations.push(`::${level}::[${f.req}] ${f.message}${suffix}`);
    summary.push(`- **${level.toUpperCase()}** \`${f.req}\` ${f.message}`);
  }
  if (findings.length === 0) summary.push('All conformance checks passed.');

  const hardCount = findings.filter((f) => !f.soft).length;
  const exitCode = enforce && hardCount > 0 ? 1 : 0;
  return { exitCode, annotations, summary: summary.join('\n') };
}

function parseArgs(argv) {
  const args = { target: '.' };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') args.target = argv[++i];
  }
  return args;
}

function main() {
  const { target } = parseArgs(process.argv.slice(2));
  const enforce = process.env.ENFORCE === 'true';

  const ctx = loadCtx(target);
  const findings = runChecks(ctx);
  const { exitCode, annotations, summary } = report(findings, { enforce });

  for (const line of annotations) console.log(line);
  if (process.env.GITHUB_STEP_SUMMARY) {
    try {
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
    } catch {
      /* step summary is best-effort */
    }
  }
  if (findings.length === 0) {
    console.log('conformance: all checks passed.');
  } else if (!enforce) {
    console.log(`conformance: ${findings.length} finding(s) in WARN mode (ENFORCE=false) — not failing the build.`);
  }
  process.exit(exitCode);
}

// Run the CLI only when invoked directly (not when imported by tests).
const invoked = process.argv[1] ? realpathSync(process.argv[1]) : '';
if (invoked && invoked === realpathSync(fileURLToPath(import.meta.url))) {
  main();
}
