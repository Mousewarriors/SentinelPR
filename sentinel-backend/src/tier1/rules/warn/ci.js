/**
 * CI/CD & GitHub Actions WARN rules
 *
 * Philosophy:
 * - CI is a top-tier real-world attack surface.
 * - These rules focus on widely agreed dangerous patterns.
 * - Keep PR noise low: strict caps, minimal annotations.
 */

export const C401_PR_TARGET_CHECKOUT_UNTRUSTED = {
    id: "C401_PR_TARGET_CHECKOUT_UNTRUSTED",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["WORKFLOW_EVENT_PULL_REQUEST_TARGET", "ACTIONS_CHECKOUT_PRESENT", "CHECKOUT_REF_UNTRUSTED_OR_MISSING"], withinSameHunk: true, withinLines: 200 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "pull_request_target", shortLabel: "PR target checkout", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "pull_request_target may checkout untrusted code", description: "A workflow using pull_request_target appears to check out code in a way that may execute untrusted PR content.", risk: "If untrusted PR code runs in a context that has access to secrets, attackers can exfiltrate secrets via CI.", confidenceRationale: "The pull_request_target event is deterministic to detect; whether checkout is safe depends on ref handling and subsequent steps.", recommendation: "Avoid running untrusted PR code with secrets. Ensure checkout ref is pinned to trusted refs, and do not run PR code in privileged contexts." }
};

export const C402_PR_TARGET_SECRETS_EXPOSED = {
    id: "C402_PR_TARGET_SECRETS_EXPOSED",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["WORKFLOW_EVENT_PULL_REQUEST_TARGET", "SECRETS_CONTEXT_REFERENCED"], withinSameHunk: true, withinLines: 250 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Secrets exposure", shortLabel: "Secrets", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Secrets referenced in pull_request_target workflow", description: "A pull_request_target workflow references GitHub secrets context.", risk: "If any untrusted PR-controlled code or inputs are executed, secrets may be exfiltrated.", confidenceRationale: "Secrets context usage and event type are deterministic; exploitability depends on subsequent execution of untrusted content.", recommendation: "Avoid using secrets in pull_request_target workflows unless you are strictly operating on trusted code and inputs." }
};

export const C403_UNPINNED_ACTIONS_VERSION = {
    id: "C403_UNPINNED_ACTIONS_VERSION",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["^\\s*uses:\\s*[^\\s@]+\\/[^\\s@]+@(?!(?:[0-9a-f]{40}))[^\\s]+\\s*$"], negativePatterns: ["^\\s*uses:\\s*\\./"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Supply chain", shortLabel: "Unpinned action", maxFindingsPerPR: 5, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "GitHub Action not pinned to a commit SHA", description: "A workflow references an action by tag or branch instead of a full commit SHA.", risk: "If the action tag or branch is moved, CI behavior can change unexpectedly or be compromised via a supply-chain attack.", confidenceRationale: "Action references are deterministic to detect; pinning to a SHA is a best practice for reproducibility and integrity.", recommendation: "Pin actions to a full commit SHA and review update strategy for action dependencies." }
};

export const C404_CHECKOUT_PERSIST_CREDENTIALS = {
    id: "C404_CHECKOUT_PERSIST_CREDENTIALS",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ACTIONS_CHECKOUT_PRESENT", "CHECKOUT_PERSIST_CREDENTIALS_TRUE_OR_MISSING"], withinSameHunk: true, withinLines: 120 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Checkout", shortLabel: "persist-credentials", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Checkout may persist credentials", description: "actions/checkout may persist credentials (or does not explicitly disable it).", risk: "Persisted credentials can be abused by subsequent steps to push commits or access repository resources unexpectedly.", confidenceRationale: "The checkout step is identifiable; whether credentials persist depends on configuration and defaults.", recommendation: "Set persist-credentials: false unless you explicitly need it, and scope permissions to least privilege." }
};

export const C405_WORKFLOW_PERMISSIONS_WRITE_ALL = {
    id: "C405_WORKFLOW_PERMISSIONS_WRITE_ALL",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)^\\s*permissions\\s*:\\s*$[\\s\\S]*?^\\s*\\w+\\s*:\\s*write\\s*$", "(?m)^\\s*permissions\\s*:\\s*write-all\\s*$"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Permissions", shortLabel: "Write perms", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Workflow permissions may be overly broad", description: "Workflow permissions grant write access broadly.", risk: "Overly broad permissions increase blast radius if CI is compromised or if untrusted inputs are executed.", confidenceRationale: "Permissions blocks are deterministic to detect, and write access is widely considered higher risk than read-only.", recommendation: "Set permissions to the minimum required. Prefer read-only unless a step explicitly needs write access." }
};

export const C406_WORKFLOW_PERMISSIONS_ID_TOKEN_WRITE = {
    id: "C406_WORKFLOW_PERMISSIONS_ID_TOKEN_WRITE",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)^\\s*id-token\\s*:\\s*write\\s*$"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Permissions", shortLabel: "id-token", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "OIDC id-token: write enabled", description: "Workflow requests id-token: write permission (OIDC token minting).", risk: "If CI is compromised, attackers may mint OIDC tokens and access cloud resources configured for federation.", confidenceRationale: "The permission is explicit and deterministic to detect.", recommendation: "Enable id-token: write only when required and scope cloud trust policies tightly to repository, branch, and workflow." }
};

export const C407_DANGEROUS_CURL_PIPE_BASH = {
    id: "C407_DANGEROUS_CURL_PIPE_BASH",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml", "**/*.{sh,bash,zsh}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\b(curl|wget)\\b[^\\n]*\\|\\s*(bash|sh)\\b"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Remote code execution", shortLabel: "curl|bash", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Remote script execution via curl|bash", description: "A command pipes remote content directly into a shell.", risk: "If the remote content is compromised, attackers can execute arbitrary code in CI, potentially exfiltrating secrets or altering builds.", confidenceRationale: "curl|bash is an unambiguous, widely recognized risky pattern.", recommendation: "Download scripts to disk, verify integrity (pin hashes/signatures), and review before executing." }
};

export const C408_DOWNLOAD_EXECUTE_REMOTE_BINARY = {
    id: "C408_DOWNLOAD_EXECUTE_REMOTE_BINARY",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml", "**/*.{sh,bash,zsh}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\b(curl|wget)\\b[^\\n]*(https?:\\/\\/[^\\s]+)\\s*-o\\s*[^\\s]+\\s*\\n?\\s*(chmod\\s*\\+x\\s*[^\\s]+\\s*\\n?\\s*)?\\s*\\./[^\\s]+", "\\b(curl|wget)\\b[^\\n]*(https?:\\/\\/[^\\s]+)\\s*-O\\s*\\n?\\s*(chmod\\s*\\+x\\s*[^\\s]+\\s*\\n?\\s*)?\\s*\\./[^\\s]+"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Remote code execution", shortLabel: "Download+exec", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Downloaded binary/script executed without verification", description: "A workflow downloads remote content and executes it.", risk: "Executing downloaded content without integrity checks can allow supply-chain compromise of CI.", confidenceRationale: "The download+execute sequence is detectable, but whether verification exists elsewhere may vary.", recommendation: "Pin downloads to immutable versions, verify checksums/signatures, and prefer trusted package managers." }
};

export const C409_EVAL_OF_GITHUB_CONTEXT = {
    id: "C409_EVAL_OF_GITHUB_CONTEXT",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml", "**/*.{sh,bash,zsh,js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\beval\\b\\s*\\(?.*\\$\\{\\{\\s*(github\\.|inputs\\.|steps\\.|runner\\.)", "\\beval\\b\\s+\"\\$\\{\\{\\s*(github\\.|inputs\\.|steps\\.|runner\\.)"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Injection", shortLabel: "eval", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "eval used with GitHub context/inputs", description: "A workflow step appears to evaluate GitHub context or inputs dynamically using eval.", risk: "If attacker-controlled values reach eval, this can lead to command injection in CI.", confidenceRationale: "Use of eval combined with interpolated context is deterministic and widely considered unsafe.", recommendation: "Avoid eval. Use explicit argument passing, safe quoting, and structured APIs instead." }
};

export const C410_SHELL_INJECTION_UNTRUSTED_INPUTS = {
    id: "C410_SHELL_INJECTION_UNTRUSTED_INPUTS",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)^\\s*run\\s*:\\s*.*\\$\\{\\{\\s*github\\.event\\.", "(?m)^\\s*run\\s*:\\s*.*\\$\\{\\{\\s*github\\.head_ref\\s*\\}\\}", "(?m)^\\s*run\\s*:\\s*.*\\$\\{\\{\\s*github\\.ref_name\\s*\\}\\}"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Injection", shortLabel: "Untrusted input", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Shell command may interpolate untrusted PR data", description: "A workflow run step interpolates GitHub event data into a shell command.", risk: "If untrusted PR fields (titles, branch names, etc.) are interpolated, shell injection may occur.", confidenceRationale: "Interpolation is detectable; exploitability depends on quoting and workflow trigger boundaries.", recommendation: "Avoid interpolating untrusted values into shell commands. Use safe quoting or pass values via environment with strict validation." }
};

export const C411_SECRETS_TO_FORK_PR = {
    id: "C411_SECRETS_TO_FORK_PR",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: false, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["WORKFLOW_EVENT_PULL_REQUEST", "SECRETS_CONTEXT_REFERENCED", "NO_FORK_GUARD_PRESENT"], withinSameHunk: false, withinLines: 400 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Secrets exposure", shortLabel: "Fork guard", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Secrets used in pull_request workflow without obvious fork guard", description: "A pull_request workflow references secrets without an obvious guard against forks.", risk: "Forked PRs are untrusted; exposing secrets to untrusted builds can lead to credential theft.", confidenceRationale: "Fork-safety depends on repository settings and guards; static analysis cannot confirm all protections.", recommendation: "Avoid secrets in pull_request workflows for forks. Use pull_request_target with strict patterns or add explicit fork guards." }
};

export const C412_WORKFLOW_DISPATCH_INPUTS_TO_SHELL = {
    id: "C412_WORKFLOW_DISPATCH_INPUTS_TO_SHELL",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["WORKFLOW_EVENT_WORKFLOW_DISPATCH", "WORKFLOW_INPUTS_DEFINED", "RUN_USES_INPUTS_INTERPOLATION"], withinSameHunk: true, withinLines: 300 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Injection", shortLabel: "dispatch inputs", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "workflow_dispatch inputs used in shell command", description: "workflow_dispatch inputs appear to be interpolated into a shell run step.", risk: "If inputs are not validated, this can lead to command injection in CI.", confidenceRationale: "Interpolation is detectable but safe usage depends on validation and quoting.", recommendation: "Validate inputs strictly, avoid direct interpolation into shell commands, and prefer structured arguments." }
};

export const C413_USE_OF_PULL_REQUEST_TARGET = {
    id: "C413_USE_OF_PULL_REQUEST_TARGET",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)^\\s*pull_request_target\\s*:\\s*$"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "pull_request_target", shortLabel: "PR target", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "pull_request_target workflow added", description: "A workflow uses the pull_request_target event.", risk: "pull_request_target runs with the base repository context and can access secrets; it requires careful handling of untrusted PR data.", confidenceRationale: "The event is explicit and deterministic to detect.", recommendation: "Ensure the workflow never executes untrusted PR code with secrets and uses safe checkout/ref patterns." }
};

export const C414_MISSING_CONCURRENCY_GUARD = {
    id: "C414_MISSING_CONCURRENCY_GUARD",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: false, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["WORKFLOW_HAS_MUTATING_STEPS", "NO_CONCURRENCY_BLOCK_PRESENT"], withinSameHunk: false, withinLines: 500 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Reliability", shortLabel: "Concurrency", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Concurrency controls may be missing", description: "A workflow with potentially mutating steps does not appear to declare concurrency controls.", risk: "Concurrent runs may race, causing unintended deployments, stale artifact publishing, or state corruption.", confidenceRationale: "Mutating step detection is heuristic; concurrency needs vary by workflow design.", recommendation: "Consider adding a concurrency group for workflows that deploy, publish, or mutate state." }
};

export const C415_CACHE_POISONING_RISK = {
    id: "C415_CACHE_POISONING_RISK",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ACTIONS_CACHE_USED", "CACHE_KEY_FROM_UNTRUSTED_CONTEXT"], withinSameHunk: true, withinLines: 250 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Caching", shortLabel: "Cache key", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Cache key may use untrusted input", description: "A cache key appears to include untrusted context values.", risk: "Cache poisoning can allow attackers to influence cached artifacts or dependencies used in later runs.", confidenceRationale: "Cache usage is detectable, but whether input is attacker-controlled depends on trigger and repository settings.", recommendation: "Use deterministic cache keys based on lockfiles and trusted refs. Avoid PR-controlled values in cache keys." }
};

export const C416_ARTIFACT_DOWNLOAD_EXECUTE = {
    id: "C416_ARTIFACT_DOWNLOAD_EXECUTE",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ACTIONS_DOWNLOAD_ARTIFACT_USED", "EXECUTES_DOWNLOADED_CONTENT"], withinSameHunk: true, withinLines: 350 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Artifacts", shortLabel: "Artifact exec", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Downloaded artifact may be executed", description: "A workflow downloads an artifact and appears to execute its contents.", risk: "Executing artifacts without integrity checks can allow artifact poisoning or supply-chain compromise between jobs.", confidenceRationale: "This is heuristic; safe usage depends on trust boundaries between jobs and artifact origin.", recommendation: "Ensure artifacts come from trusted jobs, validate contents, and avoid executing arbitrary artifact payloads." }
};

export const C417_SECRETS_LOGGED = {
    id: "C417_SECRETS_LOGGED",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)^\\s*run\\s*:\\s*.*(echo|printf)\\s+\\$\\{\\{\\s*secrets\\.[A-Za-z0-9_]+\\s*\\}\\}", "(?m)^\\s*run\\s*:\\s*.*\\$\\{\\{\\s*secrets\\.[A-Za-z0-9_]+\\s*\\}\\}\\s*\\|"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Secrets exposure", shortLabel: "Secret log", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Secret value may be printed in workflow logs", description: "A workflow step appears to print a secret value.", risk: "Secrets printed to logs may be captured by log systems or exposed to contributors depending on settings.", confidenceRationale: "Direct printing of secrets context is deterministic and widely considered unsafe.", recommendation: "Do not print secrets. Use masked variables and pass secrets only to tools that require them." }
};

export const C418_ENVFILE_INJECTION = {
    id: "C418_ENVFILE_INJECTION",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)\\$GITHUB_ENV\\b.*\\$\\{\\{\\s*github\\.event\\.", "(?m)\\$GITHUB_OUTPUT\\b.*\\$\\{\\{\\s*github\\.event\\."] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Injection", shortLabel: "Envfile", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "GitHub env/output file may include untrusted data", description: "A workflow writes GitHub event data to $GITHUB_ENV or $GITHUB_OUTPUT.", risk: "If untrusted data is written to env/output files without sanitization, it can lead to injection issues in later steps.", confidenceRationale: "The pattern is detectable, but exploitability depends on sanitization and subsequent consumption.", recommendation: "Sanitize values written to env/output files and avoid writing untrusted PR fields directly." }
};

export const C419_UNTRUSTED_REF_CHECKOUT = {
    id: "C419_UNTRUSTED_REF_CHECKOUT",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ACTIONS_CHECKOUT_PRESENT", "CHECKOUT_REF_FROM_EVENT_OR_INPUTS"], withinSameHunk: true, withinLines: 160 } },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Checkout", shortLabel: "Checkout ref", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Checkout ref may be derived from untrusted input", description: "actions/checkout ref appears to be derived from GitHub event context or workflow inputs.", risk: "Checking out attacker-controlled refs can cause untrusted code execution in privileged contexts.", confidenceRationale: "The ref assignment pattern is detectable; safety depends on the workflow trigger and trust boundary.", recommendation: "Pin checkout to trusted refs for privileged workflows and validate any input-derived refs against allowlists." }
};

export const C420_SELF_HOSTED_RUNNER_RISK = {
    id: "C420_SELF_HOSTED_RUNNER_RISK",
    tier: "TIER_1", kind: "WARN", category: "CI/CD & GitHub Actions", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "BOTH", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)^\\s*runs-on\\s*:\\s*\\[?\\s*self-hosted\\b"] },
    presentation: { group: "CI/CD & GitHub Actions", subgroup: "Runners", shortLabel: "Self-hosted", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Self-hosted runner used", description: "A workflow uses a self-hosted runner.", risk: "Self-hosted runners can increase risk if untrusted code runs on them, potentially exposing internal networks or credentials.", confidenceRationale: "runs-on: self-hosted is deterministic to detect.", recommendation: "Ensure self-hosted runners are isolated, ephemeral where possible, and do not run untrusted PR code in privileged contexts." }
};

export const WARN_CI_RULES = [
    C401_PR_TARGET_CHECKOUT_UNTRUSTED, C402_PR_TARGET_SECRETS_EXPOSED, C403_UNPINNED_ACTIONS_VERSION, C404_CHECKOUT_PERSIST_CREDENTIALS, C405_WORKFLOW_PERMISSIONS_WRITE_ALL, C406_WORKFLOW_PERMISSIONS_ID_TOKEN_WRITE, C407_DANGEROUS_CURL_PIPE_BASH, C408_DOWNLOAD_EXECUTE_REMOTE_BINARY, C409_EVAL_OF_GITHUB_CONTEXT, C410_SHELL_INJECTION_UNTRUSTED_INPUTS, C411_SECRETS_TO_FORK_PR, C412_WORKFLOW_DISPATCH_INPUTS_TO_SHELL, C413_USE_OF_PULL_REQUEST_TARGET, C414_MISSING_CONCURRENCY_GUARD, C415_CACHE_POISONING_RISK, C416_ARTIFACT_DOWNLOAD_EXECUTE, C417_SECRETS_LOGGED, C418_ENVFILE_INJECTION, C419_UNTRUSTED_REF_CHECKOUT, C420_SELF_HOSTED_RUNNER_RISK
];
