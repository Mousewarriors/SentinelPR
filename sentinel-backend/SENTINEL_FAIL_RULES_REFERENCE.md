# SentinelPR Tier 1 Reference: FAIL Rules & Secrets Regexes

This document serves as a reference for the current detection logic in SentinelPR's Tier 1 Static Analysis.

---

## 1. Tier 1 FAIL Rules (Consolidated)

These rules block PRs upon detection.

| ID | Title | Category | Severity | Detection Pattern / Logic |
|---|---|---|---|---|
| **S001** | Private key committed | Secrets | CRITICAL | RSA/EC/OPENSSH/DSA PEM blocks |
| **S004** | GitHub token committed | Secrets | CRITICAL | `ghp_`, `github_pat_`, `gho_` formats |
| **SF001** | Public Function Exposure | Serverless | CRITICAL | `AuthType: NONE`, `--allow-unauthenticated` |
| **K8S001** | Privileged Container | IaC | CRITICAL | `privileged: true` |
| **K8S002** | Host Namespace Sharing | IaC | CRITICAL | `hostNetwork: true`, `hostPID: true`, `hostIPC: true` |
| **K8S003** | HostPath Volume | IaC | HIGH | `hostPath:` |
| **K8S004** | Privilege Escalation | IaC | HIGH | `allowPrivilegeEscalation: true` |
| **K8S005** | RunAsNonRoot False | IaC | HIGH | `runAsNonRoot: false` |
| **TF001** | Terraform SG World Open | IaC | CRITICAL | `0.0.0.0/0` + sensitive ports (Composite) |
| **TF002** | S3 Bucket Public | IaC | HIGH | `acl = "public-read"`, `block_public_acls = false` |
| **TF003** | IAM Wildcard | IaC | CRITICAL | Action: "*" AND Resource: "*" (Composite) |
| **AI001** | LLM Output Exec | AI/LLM | CRITICAL | `eval()` or `exec()` on variables like `modelOutput` |
| **SEC001** | CORS Wildcard + Credentials | Web | CRITICAL | `*` origin + `credentials: true` (Composite) |
| **SEC002** | CSRF Disabled | Web | HIGH | `csrf: false`, `DISABLE_CSRF=true` |
| **SEC003** | Cookie httpOnly False | Web | HIGH | `httpOnly: false` |
| **SEC004** | Cookie Secure False | Web | HIGH | `secure: false` |
| **SEC005** | SameSite=None without Secure| Web | HIGH | `sameSite: none` without `secure: true` (Composite) |
| **PATH001**| Input Path Traversal (Node) | Files | HIGH | `fs.readFile(req.query.path)` pattern |

---

## 2. Generic Secrets Regexes (WARN Pack)

These regexes are used in the secrets rule pack.

| ID | Name | Regex Pattern(s) |
|---|---|---|
| **W101** | Possible Secret Assign | `SECRET_KEYWORD_NEAR_ASSIGNMENT` + `HIGH_ENTROPY_VALUE` (Composite) |
| **W102** | Env Secret Assignment | `(?i)^(\s*)([A-Z0-9_]*?(SECRET\|TOKEN\|PASSWORD\|API_KEY\|PRIVATE_KEY\|CLIENT_SECRET)[A-Z0-9_]*)\s*=` |
| **W103** | JWT-like Token | `\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b` |
| **W104** | AWS Access Key ID | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` |
| **W105** | GCP API Key | `\bAIza[0-9A-Za-z\-_]{30,}\b` |
| **W106** | Twilio SID | `\bAC[a-f0-9]{32}\b` |
| **W112** | Basic Auth in URL | `\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/ [^\s:@/]+:[^\s@/]+@[^\s/]+\b` |
| **W116** | Secret Echoed | `echo \$\{?[A-Z0-9_]*(SECRET\|TOKEN\|PASSWORD\|API_KEY\|PRIVATE_KEY\|CLIENT_SECRET)[A-Z0-9_]*\}?` |
| **W119** | SSH Public Key | `\bssh-(rsa\|ed25519)\s+[A-Za-z0-9+/=]{20,}(\s+[^\s]+)?\b` |
| **W127** | Base64 Secret Like | `\b[A-Za-z0-9+/]{24,}={0,2}\b` |
| **W130** | Curl Example Secret | `curl.*-H.*Authorization: Bearer`, `curl.*-u.*user:pass` |

---

## 3. Current Engine Composite Markers (Detection Logic)

*   `SECRET_KEYWORD_NEAR_ASSIGNMENT`: `/(secret|token|password|key|auth|api|client).{0,30}[:=]/i`
*   `HIGH_ENTROPY_VALUE`: Entropy > 3.8 on strings like `[:=]\s*["']?([A-Za-z0-9+/=]{16,})["']?`
*   `LINE_IS_COMMENT`: `/^(\s*)(\/\/|#|\/\*|--)/`
*   `PATH_LOOKS_TEST_OR_FIXTURE`: `/(test|spec|fixture|mock|dummy)/i`
