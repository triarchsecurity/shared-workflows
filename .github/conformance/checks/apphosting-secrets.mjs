// CONF-03 — apphosting secret bindings vs provisioned Secret Manager.
//
// For each apphosting*.yaml, map file -> GCP project via
// .conformance/apphosting-projects.json, then assert every `secret: NAME`
// binding appears in .conformance/project-secrets/<project>.txt (the provisioned
// set). Catches "added a secret: binding without provisioning it" at PR time
// (the D-5 missing-KMS_KEY_NAME_DEV incident).
//
// A file whose project has no mapping or no manifest is UNREACHABLE (a customer
// project this repo's creds can't enumerate) — skipped, never a hard fail. The
// scheduled cross-repo audit owns the live `gcloud secrets list` diff.

export function check(ctx) {
  const findings = [];
  const m = ctx.manifests || {};
  const projMap = m.apphostingProjects || {};
  const projSecrets = m.projectSecrets || {};

  for (const file of m.apphostingFiles || []) {
    const project = projMap[file.name];
    if (!project) continue; // unmapped => unreachable, skip
    const provisioned = projSecrets[project];
    if (!provisioned) continue; // no manifest for project => unreachable, skip
    const provSet = new Set(provisioned);

    for (const line of file.text.split('\n')) {
      const sm = line.match(/^\s*secret:\s*([A-Za-z0-9._-]+)\s*$/);
      if (!sm) continue;
      const name = sm[1];
      if (!provSet.has(name)) {
        findings.push({
          req: 'CONF-03',
          message: `apphosting file '${file.name}' binds secret '${name}' not provisioned in project '${project}' (.conformance/project-secrets/${project}.txt)`,
          remediation: `Provision the secret in the target project's Secret Manager, then refresh .conformance/project-secrets/${project}.txt`,
        });
      }
    }
  }

  return findings;
}
