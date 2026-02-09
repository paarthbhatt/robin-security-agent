---
name: security-audit
description: "Comprehensive security audit workflow for a repository. Orchestrates reconnaissance, dependency scanning, and static analysis to produce a detailed threat report."
---

# Security Audit Skill

This skill provides a structured workflow for performing a tactical security audit on a codebase.

## Workflow

1. **Reconnaissance**: Use `github_recon` to map the repository structure and identify sensitive files (e.g., config files, entry points).
2. **Dependency Analysis**: Run `dependency_audit` to identify vulnerable third-party packages.
3. **Static Analysis**: Execute `static_analysis` on high-risk files discovered during reconnaissance.
4. **Vulnerability Mapping**: If specific vulnerability IDs are found in dependencies or code comments, use `cve_lookup` to understand the threat.
5. **Report Generation**: Synthesize all findings into a tactical report.

## Reporting Format

Lead with **Threat Level: [LOW | MEDIUM | HIGH | CRITICAL]**.

### Findings Summary
- **Dependencies**: List critical vulnerabilities in the supply chain.
- **Logic Flaws**: Identify dangerous code patterns (e.g., `eval()`, hardcoded keys).
- **Secrets**: Report any leaked credentials or tokens.

### Remediation Steps
Provide specific, actionable commands to patch the vulnerabilities (e.g., `npm update`, `chmod 600`).
