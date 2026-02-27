# Tier 1 Authoritative Rule Contract

This document defines the rules and standards for SentinelPR's Tier 1 Static Analysis.

## Core Principles
1. **Deterministic**: Rules must trigger consistently based on code patterns in the diff.
2. **High Precision**: FAIL rules must have near-zero false positives.
3. **Explanatory**: Every finding must explain *what* failed, *why* it is dangerous, and *how* to fix it.

## Mandatory Rule Fields
Every Tier 1 FAIL rule must define the following fields:
- `title`: A short, descriptive title of the issue.
- `description`: Exactly what was detected.
- `risk`: The impact of the vulnerability.
- `confidenceRationale`: Why this detection is authoritative and high-confidence.
- `recommendation`: Concrete steps to resolve the issue.

## Rule Registry (Summary)

### Domain 1: Secrets & Credentials
- **S001**: Private key material (PEM/OpenSSH) - CRITICAL
- **S002**: PGP Private Key Block - CRITICAL
- **S003**: age secret key - CRITICAL
- **S004**: GitHub Tokens - CRITICAL
- **S005**: GitLab Personal Access Token - CRITICAL
- **S006**: npm registry auth token in .npmrc - CRITICAL
- **S007**: AWS Access Key ID + Secret Pair - CRITICAL
- **S008**: GCP Service Account JSON key - CRITICAL
- **S009**: Stripe live secret key - CRITICAL
- **S009-WH**: Stripe webhook signing secret - CRITICAL
- **S010**: Slack tokens - CRITICAL
- **S011**: SendGrid API key - CRITICAL
- **S012**: Database/Cache/Message bus URLs with passwords - HIGH

### Domain 2: Dangerous Code Execution
- **E001**: JS/TS eval / Function constructor - CRITICAL
- **E002**: Node child_process shell execution - CRITICAL
- **E003**: Node vm code execution - HIGH
- **E004**: Python dangerous execution (eval/exec/subprocess shell=True) - CRITICAL
- **E005**: Ruby dangerous execution (eval/system/exec) - CRITICAL
- **E006**: PHP dangerous execution (eval/exec/system/shell_exec) - CRITICAL

### Domain 3: Transport Security Disabled
- **T001**: Node TLS verification globally disabled - CRITICAL
- **T002**: TLS verification disabled via client options - CRITICAL
- **T003**: Curl/Wget insecure flags - HIGH
- **T004**: Tooling/Package manager SSL verification disabled - HIGH

### Domain 4: Auth & Session Security
- **A001**: Cookie httpOnly explicitly disabled - HIGH
- **A002**: Cookie secure explicitly disabled - HIGH
- **A003**: sameSite set to "none" without secure: true - HIGH
- **A004**: Auth explicitly disabled (config toggles) - CRITICAL
- **A005**: CSRF explicitly disabled - CRITICAL

### Domain 5: Injection Slam-Dunks
- **I001**: Unsafe ORM APIs (e.g. $queryRawUnsafe) - CRITICAL
- **I002**: Raw SQL concatenation with request input - HIGH

### Domain 6: SSRF Slam-Dunks
- **S001-SSRF**: User-controlled URL in outbound request - HIGH

### Domain 7: CI / Supply Chain
- **C001**: "curl | sh" or "wget | bash" - CRITICAL
- **C002**: Unpinned GitHub Actions (no SHA pin) - HIGH
- **C003**: Risky pull_request_target with checkout - CRITICAL
- **C004**: Overly broad workflow permissions - HIGH

### Domain 8: Containers / K8s / IaC
- **K001**: Kubernetes privileged container - CRITICAL
- **K002**: Host networking/PID/IPC/Path exposure - CRITICAL
- **K003**: allowPrivilegeEscalation true - HIGH
- **K004**: runAsNonRoot false - HIGH
- **D001**: Dockerfile USER root - HIGH
- **F001**: Public exposure on sensitive ports (0.0.0.0/0) - CRITICAL

---

## Suppression Format
Inline suppression is supported via comments:
`sentinelpr: ignore <RULE_ID>`
This should be used only on the specific line where the finding occurs.
