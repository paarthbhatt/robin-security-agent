export const BUG_BOUNTY_TRIAGE_DESCRIPTION = [
  "Triage an explicitly authorized bug bounty target using detection-only analysis.",
  "",
  "Constraints enforced by the tool:",
  "- The target must appear in the configured scope allowlist (ROBIN_BOUNTY_SCOPES).",
  "- Analysis is passive: static analysis, dependency manifests, and CVE data only.",
  "- No exploitation, no PoC execution, no active attack traffic.",
  "",
  "Returns draft findings that require human review before any report submission.",
].join("\n");

export const BUG_BOUNTY_HANDOFF_DESCRIPTION = [
  "Prepare a human handoff summary of draft bug bounty findings.",
  "The human operator validates reproduction steps and submits the report.",
  "ROBIN never performs final exploitation or submission autonomously.",
].join("\n");
