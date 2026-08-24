/**
 * Bug bounty triage module for ROBIN.
 *
 * Implements the detection half of the "Autonomous Bug Bounty Module"
 * proposal (issue #1) with hard safety boundaries:
 *
 *  - Only operates on explicitly allowlisted, authorized program targets.
 *    Autonomous target acquisition/discovery is intentionally NOT built:
 *    scopes must be configured by a human operator.
 *  - Detection-only: passive static analysis, dependency manifests, and
 *    published CVE data. No exploitation, no PoC execution against live
 *    hosts, no credential attacks, no active attack traffic.
 *  - Findings are DRAFTS. The "alert BATMAN" step is a human handoff for
 *    review and submission, never for automated final infiltration.
 *
 * Deliberately not implemented from the proposal: autonomous PoC execution,
 * final infiltration, and payout automation.
 */

export type FindingSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info";

export interface BountyScope {
  /** Canonical program name, e.g. "HackerOne/example-org". */
  program: string;
  /** Exact in-scope hosts and repo slugs. Wildcards are rejected. */
  allowedTargets: string[];
  /** URL of the program rules / safe-harbor terms. */
  rulesUrl?: string;
  /** Reference to the authorization basis (program terms, VDP link, ...). */
  authorizationRef?: string;
}

export interface BountyScopeConfig {
  scopes: BountyScope[];
  /** Always true: findings may not leave ROBIN without human review. */
  requireHumanReview: boolean;
}

export interface DetectorResult {
  title: string;
  severity: FindingSeverity;
  /** 0..1 */
  confidence: number;
  cveIds?: string[];
  evidence?: string[];
}

/**
 * A detector MUST be passive: static analysis, dependency manifests,
 * published CVE data, or repository metadata only. Detectors must not
 * send attack traffic to targets.
 */
export interface Detector {
  name: string;
  run(target: string): Promise<DetectorResult[]> | DetectorResult[];
}

export interface BountyFinding {
  id: string;
  program: string;
  target: string;
  title: string;
  severity: FindingSeverity;
  confidence: number;
  cveIds: string[];
  evidence: string[];
  /** Documentation-only reproduction notes. Never executed by ROBIN. */
  pocNotes: string;
  detectedBy: string[];
  status: "draft" | "ready-for-human-review" | "rejected";
  createdAt: string;
}

export class ScopeViolationError extends Error {
  constructor(target: string) {
    super(
      `Target "${target}" is not in any configured bug bounty scope. ` +
        "Refusing to run: ROBIN only analyzes explicitly authorized targets."
    );
    this.name = "ScopeViolationError";
  }
}

export function normalizeTarget(target: string): string {
  return target
    .trim()
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, "")
    .replace(/\/.*$/, "");
}

function validateScopeEntry(scope: BountyScope): void {
  if (!scope.program || scope.program.trim().length === 0) {
    throw new Error("BountyScope.program must be a non-empty string.");
  }
  if (
    !Array.isArray(scope.allowedTargets) ||
    scope.allowedTargets.length === 0
  ) {
    throw new Error(
      `BountyScope "${scope.program}" has no allowedTargets. An explicit allowlist is required.`
    );
  }
  for (const t of scope.allowedTargets) {
    if (!t || t.includes("*")) {
      throw new Error(
        `BountyScope "${scope.program}" contains a wildcard or empty target "${t}". ` +
          "Targets must be listed explicitly; wildcards are not allowed."
      );
    }
  }
}

export function createScopeConfig(scopes: BountyScope[]): BountyScopeConfig {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    throw new Error(
      "At least one explicit bounty scope is required. Autonomous target discovery is disabled by design."
    );
  }
  scopes.forEach(validateScopeEntry);
  return { scopes, requireHumanReview: true };
}

/**
 * Loads scope configuration from the ROBIN_BOUNTY_SCOPES env var (JSON).
 * Example:
 *   ROBIN_BOUNTY_SCOPES='[{"program":"HackerOne/example-org","allowedTargets":["example.com","example-org/api"],"rulesUrl":"https://example.com/security/bounty"}]'
 */
export function loadScopeConfigFromEnv(
  env: Record<string, string | undefined> = process.env
): BountyScopeConfig {
  const raw = env.ROBIN_BOUNTY_SCOPES;
  if (!raw) {
    throw new Error(
      "ROBIN_BOUNTY_SCOPES is not set. Bug bounty triage requires an explicit, authorized scope list."
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("ROBIN_BOUNTY_SCOPES is not valid JSON.");
  }
  if (!Array.isArray(parsed)) {
    throw new Error(
      "ROBIN_BOUNTY_SCOPES must be a JSON array of scope objects."
    );
  }
  return createScopeConfig(parsed as BountyScope[]);
}

export function findScopeForTarget(
  target: string,
  config: BountyScopeConfig
): BountyScope | undefined {
  const normalized = normalizeTarget(target);
  return config.scopes.find((scope) =>
    scope.allowedTargets.some((t) => normalizeTarget(t) === normalized)
  );
}

export function assertTargetInScope(
  target: string,
  config: BountyScopeConfig
): BountyScope {
  const scope = findScopeForTarget(target, config);
  if (!scope) {
    throw new ScopeViolationError(target);
  }
  return scope;
}

let findingCounter = 0;

export function createFindingDraft(
  scope: BountyScope,
  target: string,
  result: DetectorResult,
  detectorName: string
): BountyFinding {
  findingCounter += 1;
  const confidence = Math.min(1, Math.max(0, result.confidence));
  return {
    id: `finding-${Date.now()}-${findingCounter}`,
    program: scope.program,
    target: normalizeTarget(target),
    title: result.title,
    severity: result.severity,
    confidence,
    cveIds: result.cveIds ?? [],
    evidence: result.evidence ?? [],
    pocNotes:
      "Documentation-only reproduction steps. ROBIN does not execute PoCs against live targets; " +
      "a human reviewer must validate and run any reproduction in an authorized environment.",
    detectedBy: [detectorName],
    status: "draft",
    createdAt: new Date().toISOString(),
  };
}

/**
 * Detection-only triage. Runs the provided (passive) detectors against an
 * in-scope target and returns draft findings. Never performs active probing
 * or exploitation. Wire existing tools (static-analysis, dependency-audit,
 * cve-lookup, github-recon) in as Detector implementations.
 */
export async function triageTarget(
  target: string,
  config: BountyScopeConfig,
  detectors: Detector[]
): Promise<BountyFinding[]> {
  const scope = assertTargetInScope(target, config);
  const findings: BountyFinding[] = [];

  for (const detector of detectors) {
    const results = await detector.run(normalizeTarget(target));
    for (const result of results) {
      findings.push(createFindingDraft(scope, target, result, detector.name));
    }
  }

  // Deduplicate identical target+title findings, keeping the strongest draft.
  const deduped = new Map<string, BountyFinding>();
  for (const finding of findings) {
    const key = `${finding.target}::${finding.title}`;
    const existing = deduped.get(key);
    if (!existing) {
      deduped.set(key, finding);
    } else {
      existing.detectedBy.push(...finding.detectedBy);
      if (finding.confidence > existing.confidence) {
        existing.confidence = finding.confidence;
        existing.severity = finding.severity;
      }
    }
  }

  return Array.from(deduped.values()).sort(
    (a, b) => b.confidence - a.confidence
  );
}

/**
 * Handoff gate: mark a draft as ready for the human operator (BATMAN), who
 * validates reproduction steps and submits the report. ROBIN takes no
 * further action after this point.
 */
export function flagForHumanReview(finding: BountyFinding): BountyFinding {
  return { ...finding, status: "ready-for-human-review" };
}

export function summarizeForOperator(findings: BountyFinding[]): string {
  if (findings.length === 0) {
    return "No draft findings. Nothing requires human review.";
  }
  const lines = findings.map(
    (f) =>
      `- [${f.severity.toUpperCase()}] ${f.title} (target: ${f.target}, program: ${f.program}, confidence: ${f.confidence.toFixed(2)}) [${f.id}]`
  );
  return (
    "Draft bug bounty findings - human review required before any report submission.\n" +
    lines.join("\n") +
    "\nNote: PoC steps are documentation-only and were not executed."
  );
}
