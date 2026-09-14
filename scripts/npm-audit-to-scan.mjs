#!/usr/bin/env node
/**
 * Turn `npm audit --json` into a scan the Triarch console will accept.
 *
 * ── WHY npm audit AND NOT A SCANNER ──────────────────────────────────────────────────────────────
 * The console's register already holds 2054 findings whose `kind` is `sca` and whose `vuln` strings
 * are GHSA/CVE identifiers — dependency advisories. That is exactly what `npm audit` produces, from
 * the same GitHub Advisory Database, against the lockfile that actually ships. Reaching for a
 * heavier scanner would add an install step, a binary to pin, and a second opinion about the same
 * advisories, to answer a question npm already answers offline in every repo that has CI.
 *
 * What this deliberately does NOT do is claim to be a code scanner. `kind: 'sca'` is stamped on
 * every finding, so nothing downstream can mistake a dependency advisory for a SAST result.
 *
 * ── EPSS AND KEV ARE FETCHED, NOT ASSUMED ────────────────────────────────────────────────────────
 * The console's assessment layer reduces a severity only when a forecast, an observation and a
 * decision model agree. Two of those three live outside npm: EPSS at FIRST.org and the KEV catalogue
 * at CISA. Both are fetched here and attached per finding, and a fetch that FAILS attaches nothing
 * rather than defaulting — a missing EPSS is "nobody forecast this", which is a different fact from
 * "forecast, and unlikely", and only the second may ever lower a severity.
 *
 * ── A CLEAN REPO STILL POSTS ─────────────────────────────────────────────────────────────────────
 * Zero findings is a RESULT. Posting nothing on a clean audit would make a healthy repo
 * indistinguishable from one whose workflow silently stopped running, which is the failure this
 * whole pipeline exists to make visible.
 *
 *   node npm-audit-to-scan.mjs --product <key> --url <base> --key <machine-key> [--dry-run]
 */
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

const arg = (name, fallback = null) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
};

const product = arg('product');
const baseUrl = (arg('url') ?? '').replace(/\/+$/, '');
const key = arg('key') ?? process.env.VULN_INGEST_KEY ?? '';
const dryRun = process.argv.includes('--dry-run');

if (!product) fail('--product is required');
if (!dryRun && !baseUrl) fail('--url is required unless --dry-run');
if (!dryRun && !key) fail('--key or VULN_INGEST_KEY is required unless --dry-run');

function fail(msg) {
  console.error(`npm-audit-to-scan: ${msg}`);
  process.exit(2);
}

/** npm audit exits NON-ZERO when it finds anything, so a non-zero exit is a result, not an error. */
function runAudit() {
  try {
    return JSON.parse(execFileSync('npm', ['audit', '--json'], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    }));
  } catch (e) {
    if (e.stdout) {
      try { return JSON.parse(e.stdout); } catch { /* fall through to the real failure */ }
    }
    fail(`npm audit produced no parseable JSON: ${e.message}`);
  }
}

const SEVERITY = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info' };

/**
 * Flatten npm's advisory graph into one finding per (package, advisory).
 *
 * npm nests advisories under `vulnerabilities[name].via`, where `via` is either a string naming
 * another package (a transitive path) or an object describing the advisory itself. Only the objects
 * are findings; the strings are edges, and counting them would multiply one CVE by however many
 * packages happen to depend on it.
 */
function toFindings(audit) {
  const out = [];
  const seen = new Set();
  for (const [name, v] of Object.entries(audit.vulnerabilities ?? {})) {
    for (const via of v.via ?? []) {
      if (typeof via === 'string') continue;
      const id = via.url?.split('/').pop() ?? via.source ?? `${name}:${via.title}`;
      const dedupe = `${name}::${id}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      out.push({
        kind: 'sca',
        severity: SEVERITY[via.severity] ?? 'info',
        vuln: `${id}${via.title ? `, ${via.title}` : ''}`,
        cwe: Array.isArray(via.cwe) ? via.cwe[0] ?? null : via.cwe ?? null,
        family: name,
        package: name,
        version: v.range ?? null,
        // `package.json` rather than a source line: an advisory is a fact about the dependency
        // tree, and pointing at a line of our code would be an invented location.
        file: 'package.json',
        line: 0,
        _ghsa: typeof id === 'string' && id.startsWith('GHSA') ? id : null,
        _cve: via.cve ?? null,
      });
    }
  }
  return out;
}

/**
 * Resolve GHSA identifiers to CVE identifiers.
 *
 * ── WHY THIS IS NOT OPTIONAL ─────────────────────────────────────────────────────────────────────
 * npm audit reports GHSA ids. EPSS and the CISA KEV catalogue are both keyed by CVE. Without this
 * step every finding arrives with no EPSS score and no KEV flag, the console's exploitability
 * factor requires both, and the assessment layer goes inert — which is the exact state this whole
 * change set exists to end: 2054 findings whose assessed severity had never once differed from raw.
 *
 * Measured on the first dry run: 4 findings, `epss=0 scored`. Not a rounding error — a silent zero.
 *
 * GitHub's advisory API is public and unauthenticated at a low rate limit; `GITHUB_TOKEN` lifts it
 * and is present in every Actions run. An unresolvable GHSA yields null, and null means unscored,
 * which cannot lower a severity.
 */
async function ghsaToCve(ids) {
  const map = new Map();
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'triarch-vuln-scan/1' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  for (const id of [...new Set(ids.filter((i) => typeof i === 'string' && i.startsWith('GHSA')))]) {
    try {
      const res = await fetch(`https://api.github.com/advisories/${id}`, {
        headers, signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) continue;
      const body = await res.json();
      if (body.cve_id) map.set(id, body.cve_id);
    } catch { /* unresolved stays unresolved, which is the honest outcome */ }
  }
  return map;
}

/** CISA KEV. A fetch failure attaches nothing — absence of evidence, never evidence of absence. */
async function kevSet() {
  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(20_000) },
    );
    if (!res.ok) return null;
    const body = await res.json();
    return new Set((body.vulnerabilities ?? []).map((v) => v.cveID));
  } catch {
    return null;
  }
}

/** EPSS, batched. Same rule: a failed or missing score stays null and cannot lower anything. */
async function epssScores(cves) {
  const scores = new Map();
  const list = [...new Set(cves.filter(Boolean))];
  for (let i = 0; i < list.length; i += 100) {
    const batch = list.slice(i, i + 100);
    try {
      const res = await fetch(
        `https://api.first.org/data/v1/epss?cve=${batch.join(',')}`,
        { signal: AbortSignal.timeout(20_000) },
      );
      if (!res.ok) continue;
      const body = await res.json();
      for (const row of body.data ?? []) {
        const n = Number(row.epss);
        if (Number.isFinite(n)) scores.set(row.cve, n);
      }
    } catch { /* this batch stays unscored, which is the honest outcome */ }
  }
  return scores;
}

const startedAt = new Date().toISOString();
const audit = runAudit();
const findings = toFindings(audit);

// GHSA -> CVE first: both downstream lookups are keyed by CVE, so resolving is what makes them
// possible at all rather than an enrichment on top of them.
const cveById = await ghsaToCve(findings.map((f) => f._ghsa));
for (const f of findings) {
  if (!f._cve && f._ghsa && cveById.has(f._ghsa)) f._cve = cveById.get(f._ghsa);
}

const [kev, epss] = await Promise.all([
  kevSet(),
  epssScores(findings.map((f) => f._cve)),
]);

for (const f of findings) {
  const cve = f._cve;
  // `kev === null` means the catalogue was unreachable. Stamping `false` would assert "not on KEV"
  // on no evidence, and KEV is the one signal that BLOCKS every reduction — getting it wrong in
  // that direction silently permits reductions the catalogue would have refused.
  if (kev && cve) f.kev = kev.has(cve);
  if (cve && epss.has(cve)) f.epssScore = epss.get(cve);
  delete f._ghsa;
  delete f._cve;
}

const scan = {
  scanId: randomUUID(),
  startedAt,
  commitSha: process.env.GITHUB_SHA ?? null,
  scannerVersion: `npm-audit/${audit.metadata?.npmVersion ?? 'unknown'}`,
  suppressedCount: 0,
  findings,
};

const summary = findings.reduce((acc, f) => {
  acc[f.severity] = (acc[f.severity] ?? 0) + 1;
  return acc;
}, {});
/*
 * The enrichment counters are printed on purpose, and `resolved` is the one that matters.
 *
 * A run reporting `resolved=0` has produced findings the console cannot assess — no CVE means no
 * EPSS and no KEV, and the exploitability factor requires both. It would still post, still look
 * successful, and quietly leave the assessed column equal to the raw one. Rendering the number is
 * what makes that visible in a log rather than six months later in a register.
 */
console.log(`product=${product} findings=${findings.length} ${JSON.stringify(summary)}`
  + ` resolved=${cveById.size}/${findings.length} ghsa->cve`
  + ` kev=${kev ? 'fetched' : 'UNREACHABLE'} epss=${epss.size} scored`);

if (dryRun) {
  console.log(JSON.stringify(scan, null, 2).slice(0, 4000));
  process.exit(0);
}

// A clean repo still posts. Zero findings is a RESULT, and silence would make a healthy repo
// indistinguishable from a workflow that quietly stopped running.
const res = await fetch(`${baseUrl}/api/ingest/vuln`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    idempotencyKey: scan.scanId,
    payload: scan,
  }),
  signal: AbortSignal.timeout(60_000),
});

const text = await res.text();
if (!res.ok) {
  console.error(`ingest refused ${res.status}: ${text.slice(0, 300)}`);
  process.exit(1);
}
console.log(`ingest accepted: ${text.slice(0, 300)}`);
