/**
 * Dependencies & Supply Chain WARN rules
 *
 * Philosophy:
 * - Supply-chain risks are a major SaaS security concern.
 * - These rules remain low-noise and focus on widely-agreed risky patterns:
 *   unpinned versions, VCS/URL dependencies, install scripts, lockfile bypass,
 *   registry overrides, and integrity/immutability issues.
 */

export const D501_LOCKFILE_REMOVED_OR_DISABLED = {
    id: "D501_LOCKFILE_REMOVED_OR_DISABLED",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/poetry.lock", "**/Pipfile.lock", "**/Gemfile.lock", "**/composer.lock"], scanMode: "DIFF", diffLines: "REMOVED_ONLY", maxFileSizeKB: 2048, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["FILE_DELETED"], withinSameHunk: false } },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Lockfiles", shortLabel: "Lockfile removed", maxFindingsPerPR: 5, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Lockfile removed", description: "A dependency lockfile was removed from the repository.", risk: "Removing lockfiles reduces build reproducibility and increases supply-chain risk by allowing dependency versions to float unexpectedly.", confidenceRationale: "Deletion of a known lockfile is deterministic and always meaningful.", recommendation: "Restore lockfiles and ensure CI installs dependencies using locked, reproducible versions." }
};

export const D502_DEPENDENCY_ADDED_UNPINNED = {
    id: "D502_DEPENDENCY_ADDED_UNPINNED",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/package.json", "**/pyproject.toml", "**/requirements*.txt", "**/Gemfile", "**/composer.json"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["DEPENDENCY_DECLARATION_LINE", "VERSION_RANGE_IS_LOOSE"], withinSameHunk: true, withinLines: 1 } },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Version pinning", shortLabel: "Unpinned dep", maxFindingsPerPR: 5, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Dependency version may be loosely pinned", description: "A dependency was added with a broad version range or without a strict pin.", risk: "Loose version constraints can pull unexpected versions, increasing breakage and supply-chain risk if upstream is compromised.", confidenceRationale: "Loose pins are detectable, but strictness requirements vary by team policy.", recommendation: "Prefer tighter version constraints and rely on lockfiles to ensure reproducibility." }
};

export const D503_DEPENDENCY_GIT_URL = {
    id: "D503_DEPENDENCY_GIT_URL",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/package.json", "**/requirements*.txt", "**/Gemfile", "**/composer.json", "**/pyproject.toml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(git\\+https|git\\+ssh|ssh://git|git@github\\.com|github\\.com/[^\\s]+\\.git)\\b", "(?i)\\bfrom:\\s*['\"]git\\+"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "VCS dependencies", shortLabel: "Git dep", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "VCS dependency added", description: "A dependency appears to be sourced directly from a Git repository.", risk: "VCS dependencies may bypass registry protections and can change unexpectedly if not pinned to immutable commits.", confidenceRationale: "Git URL patterns are deterministic to detect.", recommendation: "Pin VCS dependencies to a commit SHA and prefer registry packages where possible." }
};

export const D504_DEPENDENCY_HTTP_URL = {
    id: "D504_DEPENDENCY_HTTP_URL",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/package.json", "**/requirements*.txt", "**/composer.json", "**/Gemfile", "**/pyproject.toml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\bhttp:\\/\\/[^\\s'\"\\)]+\\b"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "URL dependencies", shortLabel: "HTTP URL dep", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Dependency source uses HTTP", description: "A dependency or package source appears to use an insecure HTTP URL.", risk: "HTTP sources can be modified by network attackers, enabling dependency tampering and compromise.", confidenceRationale: "HTTP URLs are deterministic to detect and are broadly considered unsafe for dependency sources.", recommendation: "Use HTTPS sources only and verify integrity (hashes/signatures) for downloaded artifacts." }
};

export const D505_NPM_POSTINSTALL_ADDED = {
    id: "D505_NPM_POSTINSTALL_ADDED",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/package.json"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)\"postinstall\"\\s*:\\s*\"[^\"]+\""] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Install scripts", shortLabel: "postinstall", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "npm postinstall script added/modified", description: "A postinstall script was added or modified in package.json.", risk: "Install scripts execute automatically in CI and developer machines, and are a common supply-chain compromise vector.", confidenceRationale: "postinstall is a deterministic field and is widely recognized as sensitive.", recommendation: "Review postinstall scripts carefully, minimize use, and prefer safer build steps in controlled CI contexts." }
};

export const D506_NPM_PREPARE_INSTALL_SCRIPT_ADDED = {
    id: "D506_NPM_PREPARE_INSTALL_SCRIPT_ADDED",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/package.json"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)\"(prepare|preinstall|install|prepublishOnly)\"\\s*:\\s*\"[^\"]+\""] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Install scripts", shortLabel: "install scripts", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "npm install lifecycle script added/modified", description: "An npm lifecycle script (prepare/preinstall/install/prepublishOnly) was added or modified.", risk: "Lifecycle scripts can execute automatically during installs and publishing, expanding supply-chain risk.", confidenceRationale: "These script fields are deterministic and commonly abused in compromised packages.", recommendation: "Review scripts carefully. Avoid unnecessary lifecycle scripts and restrict what they can execute." }
};

export const D507_PIP_UNPINNED_REQUIREMENT = {
    id: "D507_PIP_UNPINNED_REQUIREMENT",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/requirements*.txt"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["^(?!\\s*(-r|--requirement|#|--)).+[^=<>!~]=?[^=].*$"], negativePatterns: ["==", "@", "git\\+", "http"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Version pinning", shortLabel: "Unpinned pip", maxFindingsPerPR: 8, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Python requirement may be unpinned", description: "A Python requirement was added without a strict version pin.", risk: "Unpinned dependencies can pull unexpected versions, increasing breakage and supply-chain risk.", confidenceRationale: "Requirements file lines are easy to detect, but pinning policies vary across projects.", recommendation: "Prefer pinned versions and lockfiles (pip-tools/poetry) for reproducible builds." }
};

export const D508_PIP_VCS_REQUIREMENT = {
    id: "D508_PIP_VCS_REQUIREMENT",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/requirements*.txt", "**/pyproject.toml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bgit\\+https://", "(?i)\\bgit\\+ssh://", "(?i)@\\s*git\\+"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "VCS dependencies", shortLabel: "pip git", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Python VCS dependency added", description: "A Python dependency appears to be sourced directly from a Git repository.", risk: "VCS dependencies can change unexpectedly unless pinned to immutable commits, increasing supply-chain risk.", confidenceRationale: "VCS URL patterns are deterministic to detect.", recommendation: "Pin to a commit SHA and prefer registry packages with lockfiles where possible." }
};

export const D509_RUBY_GEM_GIT_SOURCE = {
    id: "D509_RUBY_GEM_GIT_SOURCE",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/Gemfile", "**/*.gemspec"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bgem\\s+['\"][^'\"]+['\"],\\s*:git\\s*=>\\s*['\"]", "(?i):git\\s*=>\\s*['\"]"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "VCS dependencies", shortLabel: "Gem git", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Ruby gem sourced from Git", description: "A Ruby dependency appears to be sourced directly from Git.", risk: "Git-sourced gems may bypass registry integrity controls and can change unless pinned to a commit.", confidenceRationale: "Gemfile Git source patterns are deterministic to detect.", recommendation: "Pin Git dependencies to a specific commit and prefer published gems where possible." }
};

export const D510_RUBY_GEMSPEC_EXEC = {
    id: "D510_RUBY_GEMSPEC_EXEC",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.gemspec"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 256, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(`|system\\(|exec\\()"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Build scripts", shortLabel: "gemspec exec", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Command execution in gemspec", description: "A gemspec appears to execute shell commands.", risk: "Build-time command execution can run during packaging/installation and is a common supply-chain compromise vector.", confidenceRationale: "Execution constructs are detectable; intent requires review.", recommendation: "Avoid executing shell commands in gemspecs. Keep build logic minimal and reproducible." }
};

export const D511_PHP_COMPOSER_UNPINNED = {
    id: "D511_PHP_COMPOSER_UNPINNED",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/composer.json"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\"[a-z0-9_.-]+\\/[a-z0-9_.-]+\"\\s*:\\s*\"\\^|~|\\*|>=|dev-"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Version pinning", shortLabel: "Composer pin", maxFindingsPerPR: 6, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Composer dependency may be loosely pinned", description: "A Composer dependency was added with a broad version constraint.", risk: "Loose constraints can pull unexpected versions, increasing supply-chain and stability risk.", confidenceRationale: "Constraint operators are detectable, but acceptable ranges vary by team policy.", recommendation: "Prefer stable constraints and ensure composer.lock is committed and used in CI." }
};

export const D512_PHP_COMPOSER_VCS_REPO = {
    id: "D512_PHP_COMPOSER_VCS_REPO",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/composer.json"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\"repositories\"\\s*:\\s*\\[", "(?i)\"type\"\\s*:\\s*\"vcs\""] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "VCS dependencies", shortLabel: "Composer VCS", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Composer VCS repository configured", description: "composer.json defines a VCS repository source.", risk: "Custom VCS repositories can bypass Packagist protections and may introduce supply-chain risk if not pinned and reviewed.", confidenceRationale: "Composer VCS configuration is deterministic to detect.", recommendation: "Pin to immutable commits/tags and ensure repository sources are trusted and reviewed." }
};

export const D513_REGISTRY_OVERRIDE_ADDED = {
    id: "D513_REGISTRY_OVERRIDE_ADDED",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/.npmrc", "**/.yarnrc", "**/.yarnrc.yml", "**/pip.conf", "**/pip.ini", "**/.pypirc", "**/Gemfile", "**/bundler/config", "**/composer.json"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 256, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: false, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)registry\\s*=", "(?i)@[^:]+:registry=", "(?i)index-url\\s*=", "(?i)extra-index-url\\s*=", "(?i)\"packagist\"\\s*:\\s*false"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Registry", shortLabel: "Registry override", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Package registry/source override added", description: "Configuration changes add or modify package registry sources.", risk: "Changing registry sources can enable dependency confusion or redirect installs to untrusted repositories.", confidenceRationale: "Registry/source override settings are deterministic to detect and widely considered security-sensitive.", recommendation: "Ensure registries are trusted and authenticated. Prefer explicit allowlists and review any private registry configurations." }
};

export const D514_NPMRC_INSECURE_SETTINGS = {
    id: "D514_NPMRC_INSECURE_SETTINGS",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/.npmrc", "**/.yarnrc", "**/.yarnrc.yml"], scanMode: "BOTH", diffLines: "ADDED_ONLY", maxFileSizeKB: 128, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)strict-ssl\\s*=\\s*false", "(?i)always-auth\\s*=\\s*false", "(?i)unsafe-perm\\s*=\\s*true"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Registry", shortLabel: "Insecure npmrc", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Insecure package manager setting added", description: "A package manager configuration disables safety controls (e.g., strict SSL).", risk: "Disabling integrity/transport safeguards can enable dependency tampering and MITM attacks.", confidenceRationale: "These settings are explicit and deterministic to detect.", recommendation: "Avoid disabling strict SSL or other safeguards. Use trusted registries and proper certificates." }
};

export const D515_LOCKFILE_LARGE_DIFF = {
    id: "D515_LOCKFILE_LARGE_DIFF",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/poetry.lock", "**/Pipfile.lock", "**/Gemfile.lock", "**/composer.lock"], scanMode: "DIFF", diffLines: "ADDED_AND_REMOVED", maxFileSizeKB: 8192, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["LOCKFILE_CHANGED_MANY_LINES"], withinSameHunk: false } },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Lockfiles", shortLabel: "Large lockfile", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Large lockfile change", description: "A lockfile changed substantially in this PR.", risk: "Large lockfile diffs can hide unexpected dependency updates and increase supply-chain review difficulty.", confidenceRationale: "Change size is measurable, but not inherently unsafe.", recommendation: "Review lockfile diffs or regenerate with a trusted workflow. Consider splitting dependency updates into smaller PRs." }
};

export const D516_DEPENDENCY_NAME_SUSPICIOUS = {
    id: "D516_DEPENDENCY_NAME_SUSPICIOUS",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/package.json", "**/requirements*.txt", "**/Gemfile", "**/composer.json", "**/pyproject.toml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F]", "(?i)\\b(dep|package|gem)\\b.*[_.-]{3,}"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Typosquatting signals", shortLabel: "Suspicious name", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Dependency name may be suspicious", description: "A dependency name includes characters or patterns that may warrant review.", risk: "Typosquatting and homoglyph attacks can trick developers into installing malicious packages.", confidenceRationale: "This is a heuristic signal; many legitimate packages may trigger it depending on naming conventions.", recommendation: "Verify the dependency is the intended package and comes from the correct publisher/namespace." }
};

export const D517_NEW_PACKAGE_MANAGER_TOOLING = {
    id: "D517_NEW_PACKAGE_MANAGER_TOOLING",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "LOW", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 2048, textOnly: false },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\bpnpm-lock\\.yaml\\b", "\\byarn\\.lock\\b", "\\bpoetry\\.lock\\b", "\\bPipfile\\.lock\\b", "\\bGemfile\\.lock\\b", "\\bcomposer\\.lock\\b", "\\bpackage-lock\\.json\\b"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Tooling", shortLabel: "New tooling", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "New package manager tooling detected", description: "New lockfile or package manager tooling appears to be introduced.", risk: "Changing tooling can alter dependency resolution and integrity guarantees.", confidenceRationale: "Lockfile/tooling file names are deterministic to detect.", recommendation: "Confirm the team intends to switch tooling and update CI to enforce reproducible installs." }
};

export const D518_CI_INSTALLS_WITHOUT_LOCKFILE = {
    id: "D518_CI_INSTALLS_WITHOUT_LOCKFILE",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: [".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?m)^\\s*run\\s*:\\s*.*\\b(npm install|yarn install|pnpm install|pip install|bundle install|composer install)\\b"], negativePatterns: ["(?i)--frozen-lockfile", "(?i)--immutable", "(?i)--locked", "(?i)--require-hashes", "(?i)--no-update", "(?i)--deployment", "(?i)ci\\b"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "CI integrity", shortLabel: "Install flags", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "CI install may not be locked/immutable", description: "A CI install command was added without obvious lockfile/immutable flags.", risk: "Non-immutable installs can resolve different dependency versions over time, increasing supply-chain and reproducibility risk.", confidenceRationale: "Install commands are detectable, but teams vary in how they enforce locking.", recommendation: "Use immutable install modes (npm ci, yarn --immutable, pnpm --frozen-lockfile, pip --require-hashes) where appropriate." }
};

export const D519_DOCKER_BASE_IMAGE_LATEST = {
    id: "D519_DOCKER_BASE_IMAGE_LATEST",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 256, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)^\\s*FROM\\s+[^\\s:]+(:latest)?\\s*$", "(?i)^\\s*FROM\\s+[^\\s:]+\\s*$"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Containers", shortLabel: "Base image", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Docker base image may be unpinned", description: "A Docker base image was added without a specific version tag or digest.", risk: "Unpinned base images can change over time, leading to non-reproducible builds and supply-chain risk if an upstream image is compromised.", confidenceRationale: "FROM lines are deterministic to detect; best practice is to pin tags and ideally digests.", recommendation: "Pin base images to specific versions and consider pinning to immutable digests for maximum reproducibility." }
};

export const D520_BINARY_DEPENDENCY_DOWNLOAD = {
    id: "D520_BINARY_DEPENDENCY_DOWNLOAD",
    tier: "TIER_1", kind: "WARN", category: "Dependencies & Supply Chain", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{sh,bash,zsh,ps1,cmd}", ".github/workflows/**/*.yml", ".github/workflows/**/*.yaml"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\b(curl|wget)\\b[^\\n]*(https?:\\/\\/[^\\s]+)\\s*(-o\\s*[^\\s]+|-O)\\b", "\\b(chmod\\s*\\+x\\s+[^\\s]+)\\b"] },
    presentation: { group: "Dependencies & Supply Chain", subgroup: "Binary downloads", shortLabel: "Binary dl", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Binary or script downloaded during build", description: "A build step downloads remote content that may be executed or used as a dependency.", risk: "Downloading and executing remote artifacts without integrity checks can enable supply-chain compromise.", confidenceRationale: "The download pattern is detectable; whether execution occurs later may not be visible in the same diff hunk.", recommendation: "Prefer official package managers, pin versions, and verify checksums/signatures for downloaded artifacts." }
};

export const WARN_DEPS_RULES = [
    D501_LOCKFILE_REMOVED_OR_DISABLED, D502_DEPENDENCY_ADDED_UNPINNED, D503_DEPENDENCY_GIT_URL, D504_DEPENDENCY_HTTP_URL, D505_NPM_POSTINSTALL_ADDED, D506_NPM_PREPARE_INSTALL_SCRIPT_ADDED, D507_PIP_UNPINNED_REQUIREMENT, D508_PIP_VCS_REQUIREMENT, D509_RUBY_GEM_GIT_SOURCE, D510_RUBY_GEMSPEC_EXEC, D511_PHP_COMPOSER_UNPINNED, D512_PHP_COMPOSER_VCS_REPO, D513_REGISTRY_OVERRIDE_ADDED, D514_NPMRC_INSECURE_SETTINGS, D515_LOCKFILE_LARGE_DIFF, D516_DEPENDENCY_NAME_SUSPICIOUS, D517_NEW_PACKAGE_MANAGER_TOOLING, D518_CI_INSTALLS_WITHOUT_LOCKFILE, D519_DOCKER_BASE_IMAGE_LATEST, D520_BINARY_DEPENDENCY_DOWNLOAD
];
