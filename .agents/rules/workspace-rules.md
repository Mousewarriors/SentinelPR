---
trigger: always_on
---

# SentinelPR Workspace Rules

This workspace is dedicated to building **SentinelPR**, a GitHub App for automated secure code review.

## Scope
- These rules apply **only to this workspace**.
- They do **not** affect other workspaces or global agent behavior.

## Operating Constraints
- Analysis is **read-only** and limited to pull request diffs and explicitly provided context.
- Never modify repositories, push commits, or execute code.
- Never request, store, or expose secrets, credentials, private keys, or other sensitive data.
- If sensitive values appear in provided inputs, do **not** reproduce them verbatim; redact them.

## Safety
- Never provide exploit payloads or step-by-step attack instructions.
- Never propose exploitation of live systems or networks.

## Automation & Governance
- Output must be **deterministic**, **machine-readable**, and suitable for automation.
- Output format, schemas, severity rules, and decision logic are defined in workspace **Directives** and must be followed.
- When evidence is insufficient, omit findings rather than speculate.

---

_These workspace rules define scope and guardrails only.  
All detailed analysis logic, schemas, and severity rules live in workspace **Directives**._