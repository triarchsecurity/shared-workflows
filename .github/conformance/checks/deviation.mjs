// CONF-02 — per-repo gate/scan/PAT/WIF drift (AR#5 rule 1 mechanized).
//
// Classify each workflow by KIND (Pitfall 2: never "must have only ci-cd.yml" —
// admin legitimately carries app crons + a publisher + a guard). A workflow in a
// REGULATED class (gate/scan/pat/wif/secret-source) that is neither in the
// admin/portal sanctioned baseline NOR justified in .conformance/exemptions.yaml
// is drift. App crons and structural guards are an allowed class — no exemption.

function classify(wf) {
  const classes = new Set();
  const name = wf.name.toLowerCase();
  const text = wf.text;

  // app-cron: named *-cron or carrying a schedule trigger.
  if (name.includes('cron') || /schedule:\s*[\s\S]*?cron:/.test(text)) classes.add('app-cron');

  // structural-guard: pure structural test workflows.
  if (name.includes('guard') || name.includes('review-gate')) classes.add('structural-guard');

  // wif: the Workload Identity Federation auth stack the canonical FIREBASE_SA_KEY path lacks.
  if (text.includes('GCP_WIF_PROVIDER') || text.includes('workload_identity_provider')) {
    classes.add('wif');
  }

  // scan: bespoke per-repo security scanning (the retired D-1 shape).
  if (name.includes('scan') || /\b(semgrep|osv-scanner|gitleaks)\b/i.test(text)) classes.add('scan');

  // secret-source: a non-canonical SA / customer secret source.
  if (/CUSTOMER_[A-Z0-9_]+/.test(text)) classes.add('secret-source');

  // pat: a Personal Access Token secret reference.
  if (/[A-Z0-9_]*_PAT\b/.test(text)) classes.add('pat');

  return classes;
}

export function check(ctx) {
  const b = ctx.baseline || {};
  const sanctioned = new Set([...(b.portal_sanctioned || []), ...(b.admin_sanctioned || [])]);
  const regulated = new Set(b.regulated_classes || []);
  const exemptByWorkflow = new Set((ctx.manifests?.exemptions || []).map((e) => e.workflow));

  const findings = [];
  for (const wf of ctx.workflows || []) {
    if (wf.name === 'ci-cd.yml') continue; // CONF-04 owns the caller SHAPE
    if (sanctioned.has(wf.name)) continue; // present in a canonical repo already

    const regulatedHits = [...classify(wf)].filter((c) => regulated.has(c));
    if (regulatedHits.length === 0) continue; // only app-cron/guard/unknown => allowed
    if (exemptByWorkflow.has(wf.name)) continue; // justified in .conformance/exemptions.yaml

    findings.push({
      req: 'CONF-02',
      message: `Workflow '${wf.name}' carries regulated class(es) [${regulatedHits.join(', ')}] absent from the admin/portal baseline and not justified in .conformance/exemptions.yaml`,
      remediation: `Adopt the canonical shared-workflows solution (AR#5 rule 1), or add { workflow: ${wf.name}, class, reason, ar5_ref } to .conformance/exemptions.yaml`,
    });
  }

  return findings;
}
