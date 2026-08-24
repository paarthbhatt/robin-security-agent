import {
  ScopeViolationError,
  assertTargetInScope,
  createScopeConfig,
  flagForHumanReview,
  normalizeTarget,
  summarizeForOperator,
  triageTarget,
} from "./bug-bounty";
import type { BountyScopeConfig, Detector } from "./bug-bounty";

const validConfig = (): BountyScopeConfig =>
  createScopeConfig([
    {
      program: "HackerOne/example-org",
      allowedTargets: ["example.com", "example-org/api"],
      rulesUrl: "https://example.com/security/bounty",
    },
  ]);

describe("bug bounty scope enforcement", () => {
  it("normalizes targets by stripping scheme and path", () => {
    expect(normalizeTarget("HTTPS://Example.com/some/path")).toBe(
      "example.com"
    );
  });

  it("rejects wildcard targets", () => {
    expect(() =>
      createScopeConfig([{ program: "p", allowedTargets: ["*.example.com"] }])
    ).toThrow(/wildcard/i);
  });

  it("rejects empty scope lists", () => {
    expect(() => createScopeConfig([])).toThrow(/scope/i);
  });

  it("blocks out-of-scope targets", () => {
    expect(() =>
      assertTargetInScope("evil.example.net", validConfig())
    ).toThrow(ScopeViolationError);
  });

  it("produces draft findings for in-scope targets and gates on human review", async () => {
    const detector: Detector = {
      name: "mock-dependency-audit",
      run: () => [
        {
          title: "Vulnerable dependency: lodash@4.17.15",
          severity: "high",
          confidence: 0.9,
          cveIds: ["CVE-2020-8203"],
          evidence: ["package.json pins lodash@4.17.15"],
        },
      ],
    };

    const findings = await triageTarget("example.com", validConfig(), [
      detector,
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe("draft");
    expect(findings[0].cveIds).toContain("CVE-2020-8203");

    const reviewed = flagForHumanReview(findings[0]);
    expect(reviewed.status).toBe("ready-for-human-review");

    expect(summarizeForOperator(findings)).toMatch(/human review required/i);
  });
});
