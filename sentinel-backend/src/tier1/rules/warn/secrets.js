// W101-W110 (Existing)
export const W101_POSSIBLE_SECRET_VAR_ASSIGN = {
    id: "W101_POSSIBLE_SECRET_VAR_ASSIGN",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**", "**/routes/**", "**/controllers/**", "**/*.{env,ini,conf,json,yml,yaml,txt}"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*", "**/vendor/**", "**/*.test.*", "**/*.spec.*"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["secret", "token", "password", "passwd", "pwd", "apikey", "api_key", "private_key", "client_secret"], withinChars: 80 }, requireAssignmentContext: true, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 5 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Possible secrets", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible secret committed", description: "A high-entropy value was added near a secret-like variable or configuration key.", risk: "If this value is a real credential, it could enable unauthorized access to systems, data, or third-party services.", confidenceRationale: "The value appears random and is associated with a secret-like name, but it does not match a stable vendor credential format.", recommendation: "Confirm whether the value is a credential. If it is, revoke/rotate it and load it from a secret manager or environment variable." }
};

export const W102_POSSIBLE_SECRET_ENV_ASSIGNMENT = {
    id: "W102_POSSIBLE_SECRET_ENV_ASSIGNMENT",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.env", "**/*.env.*", ".env", ".env.*", "**/*.{ini,conf}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["SECRET", "TOKEN", "PASSWORD", "API_KEY", "PRIVATE_KEY", "CLIENT_SECRET"], withinChars: 50 }, requireAssignmentContext: true, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "CONFIG_KV", kv: { keyPatterns: ["(?i)^(\\s*)([A-Z0-9_]*?(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*)\\s*="], valuePatterns: ["^.{16,}$"] } },
    presentation: { group: "Secrets & Credentials", subgroup: "Env secrets", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible credential in environment file", description: "A secret-like environment variable assignment was added to an env/config file.", risk: "If this value is a real credential, committing it can expose production access to anyone with repository access.", confidenceRationale: "The key name strongly suggests a secret, but the value may still be a placeholder or non-sensitive value.", recommendation: "Ensure secrets are not committed. Use a secret manager or deployment environment variables instead." }
};

export const W103_JWT_LIKE_TOKEN = {
    id: "W103_JWT_LIKE_TOKEN",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,json,yml,yaml,env,txt}"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*", "**/*.md"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        requireValuePosition: true,
        patterns: ["\\beyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b"],
        negativePatterns: ["your\\.jwt\\.here", "example", "REDACTED", "YOUR_TOKEN_HERE"]
    },
    presentation: { group: "Secrets & Credentials", subgroup: "Tokens", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "JWT-like token committed", description: "A value resembling a JWT was added to the repository.", risk: "If this is a real session or API token, it may allow unauthorized access until it expires or is revoked.", confidenceRationale: "The structure matches a JWT, but JWT-like values are sometimes used in examples or tests.", recommendation: "Verify whether the token is real. If it is, revoke/rotate it and avoid committing tokens to source control." }
};

export const W104_AWS_ACCESS_KEY_ID_UNPAIRED = {
    id: "W104_AWS_ACCESS_KEY_ID_UNPAIRED",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,txt}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        requireValuePosition: true,
        patterns: ["\\b(AKIA|ASIA)[0-9A-Z]{16}\\b"],
        negativePatterns: ["AKIAIOSFODNN7EXAMPLE"]
    },
    presentation: { group: "Secrets & Credentials", subgroup: "Cloud credentials", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible AWS access key committed", description: "An AWS access key ID was added, but a corresponding secret key was not detected nearby.", risk: "If this is a real access key, it indicates cloud credentials may have been exposed or are being hardcoded.", confidenceRationale: "AWS access key IDs have a recognizable format, but the presence of the ID alone does not confirm a full credential leak.", recommendation: "Verify whether the access key is real. If so, rotate it in AWS IAM and use a secret manager or environment variables." }
};

export const W105_GCP_API_KEY = {
    id: "W105_GCP_API_KEY",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,txt}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        requireValuePosition: true,
        patterns: ["\\bAIza[0-9A-Za-z\\-_]{30,}\\b"],
        negativePatterns: ["example", "REDACTED"]
    },
    presentation: { group: "Secrets & Credentials", subgroup: "Cloud credentials", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible Google API key committed", description: "A value matching the common pattern of a Google API key was added.", risk: "If this is a real key, it may allow unauthorized use of Google APIs and could incur cost or expose data.", confidenceRationale: "The pattern matches common Google API key formats, but similar strings may appear in non-secret contexts.", recommendation: "Confirm whether the key is real. If so, restrict and rotate it, and load it from a secret manager or environment variables." }
};

export const W106_TWILIO_SID_PRESENT = {
    id: "W106_TWILIO_SID_PRESENT",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,txt}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\bAC[a-f0-9]{32}\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Third-party credentials", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Twilio account identifier committed", description: "A Twilio Account SID was added to the repository.", risk: "An Account SID is not a secret by itself, but it often accompanies an auth token. Committing both can expose Twilio access.", confidenceRationale: "The SID format is stable, but it does not confirm that a secret token is present.", recommendation: "Ensure no associated auth token is committed. Use environment variables or a secret manager for Twilio credentials." }
};

export const W107_NETRC_CREDENTIALS = {
    id: "W107_NETRC_CREDENTIALS",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/.netrc", ".netrc", "**/*netrc*"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bmachine\\b.+\\blogin\\b.+\\bpassword\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Credentials files", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Credentials file content committed", description: "A .netrc-style credential entry (machine/login/password) was added.", risk: "Committed credentials can grant direct access to remote services and may be abused by anyone with repository access.", confidenceRationale: ".netrc credential entries are an explicit format for storing login/password pairs.", recommendation: "Remove credentials from the repository and authenticate using a secret manager, CI secrets, or environment variables." }
};

export const W108_DOCKER_CONFIG_AUTH = {
    id: "W108_DOCKER_CONFIG_AUTH",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/config.json", "**/.docker/config.json"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\"auth\"\\s*:\\s*\"[A-Za-z0-9+/=]{20,}\""] },
    presentation: { group: "Secrets & Credentials", subgroup: "Credentials files", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Docker registry credentials may be committed", description: "A Docker config entry containing an auth field was added.", risk: "Docker registry credentials can allow unauthorized access to private images or enable publishing malicious images.", confidenceRationale: "Docker config auth fields are commonly base64-encoded credentials, but may occasionally be placeholders.", recommendation: "Do not commit Docker credential configs. Use CI secrets or credential helpers instead." }
};

export const W109_K8S_SECRET_SUSPICIOUS = {
    id: "W109_K8S_SECRET_SUSPICIOUS",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["K8S_KIND_SECRET", "K8S_DATA_KEYS_PRESENT"], withinSameHunk: true, withinLines: 40 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Kubernetes", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Kubernetes Secret object committed", description: "A Kubernetes Secret object was added or modified.", risk: "Committing secrets to source control may expose credentials to anyone with repository access, even if values are base64-encoded.", confidenceRationale: "Kubernetes Secret resources often contain real credentials, but some repos commit non-production or templated secrets.", recommendation: "Prefer external secret managers (e.g., ExternalSecrets, sealed secrets with proper controls) and avoid committing real secret values." }
};

export const W110_SUSPICIOUS_CONNECTION_STRING = {
    id: "W110_SUSPICIOUS_CONNECTION_STRING",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,txt,ini,conf}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true, prodHeuristics: { requireNonLocalHost: true, requireNonTestPath: true } },
    detection: { type: "REGEX", patterns: ["\\bpostgres(ql)?:\\/\\/[^\\s@]+@[^\\s/]+\\b", "\\bmysql:\\/\\/[^\\s@]+@[^\\s/]+\\b", "\\bmongodb(\\+srv)?:\\/\\/[^\\s@]+@[^\\s/]+\\b", "\\bredis(s)?:\\/\\/[^\\s@]+@[^\\s/]+\\b"], negativePatterns: ["localhost", "127\\.0\\.0\\.1", "example", "REDACTED"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Connection strings", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Connection details committed", description: "A connection string or endpoint detail was added that may point to a non-local environment.", risk: "Even without a password, committed connection endpoints can increase exposure and often accompany credentials elsewhere in the codebase.", confidenceRationale: "The string resembles a connection URI, but it may reference a non-sensitive environment or be a placeholder.", recommendation: "Confirm the endpoint is not sensitive. Prefer environment-based configuration for service endpoints and credentials." }
};

// W111-W130 (New)
export const W111_OAUTH_CLIENT_SECRET = {
    id: "W111_OAUTH_CLIENT_SECRET",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,json,yml,yaml,env,ini,conf,txt}"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*", "**/vendor/**"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["client_secret", "oauth_secret", "oauth_client_secret", "clientSecret", "CLIENT_SECRET"], withinChars: 80 }, requireAssignmentContext: true, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 5 } },
    presentation: { group: "Secrets & Credentials", subgroup: "OAuth / Identity", maxFindingsPerPR: 1, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible OAuth client secret committed", description: "A value resembling an OAuth client secret was added.", risk: "If this is a real client secret, it could allow attackers to impersonate your application when interacting with an OAuth provider.", confidenceRationale: "OAuth client secrets are typically high-entropy values but do not have a universal vendor prefix.", recommendation: "Verify whether this is a real client secret. If so, rotate it and load it from a secret manager or environment variable." }
};

export const W112_BASIC_AUTH_IN_URL = {
    id: "W112_BASIC_AUTH_IN_URL",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,json,yml,yaml,env,ini,conf,txt,md}"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true, prodHeuristics: { disallowHosts: ["localhost", "127.0.0.1"], requireNonLocalHost: true } },
    detection: { type: "REGEX", patterns: ["\\b[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/[^\\s:@/]+:[^\\s@/]+@[^\\s/]+\\b"], negativePatterns: ["localhost", "127\\.0\\.0\\.1", "REDACTED", "your_password", "example"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Credentials in URLs", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Credentials embedded in URL", description: "A URL containing embedded basic authentication credentials was added.", risk: "Credentials embedded in URLs may be logged, cached, or exposed to unintended parties.", confidenceRationale: "URLs containing username:password@host are unambiguous indicators of credential exposure.", recommendation: "Remove credentials from URLs and authenticate using secure headers or environment-based configuration." }
};

export const W113_API_KEY_JSON_CONFIG = {
    id: "W113_API_KEY_JSON_CONFIG",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.json"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["apiKey", "api_key", "apikey", "key", "token"], withinChars: 60 }, requireAssignmentContext: true, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 8 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Config files", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible API key in JSON config", description: "A potential API key was added to a JSON configuration file.", risk: "If this is a real API key, committing it may expose third-party service access.", confidenceRationale: "API keys often appear as long strings in JSON configs but are not always secrets.", recommendation: "Confirm whether the value is sensitive and migrate secrets to environment variables or a secret manager." }
};

export const W114_FIREBASE_SUPABASE_KEY = {
    id: "W114_FIREBASE_SUPABASE_KEY",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,json,yml,yaml,env,txt}"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["firebase", "supabase", "anon", "service_role", "SUPABASE", "FIREBASE"], withinChars: 120 }, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { anyOf: ["JWT_LIKE_TOKEN", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 15 } },
    presentation: { group: "Secrets & Credentials", subgroup: "BaaS keys", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Firebase/Supabase key added", description: "A Firebase or Supabase key was added.", risk: "While some keys are intended for client use, misconfigured permissions may allow data access or abuse.", confidenceRationale: "These keys and tokens can be recognizable but are sometimes non-secret, depending on role and permissions.", recommendation: "Verify the key’s role and ensure backend secrets are not committed. Apply least-privilege policies and rotate if needed." }
};

export const W115_TOKEN_IN_TEST_FIXTURE = {
    id: "W115_TOKEN_IN_TEST_FIXTURE",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,json,yml,yaml,txt,md}"], excludeGlobs: [], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "LOW", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true, prodHeuristics: { requireNonTestPath: false } },
    detection: { type: "COMPOSITE", composite: { allOf: ["PATH_LOOKS_TEST_OR_FIXTURE", "JWT_LIKE_TOKEN_OR_HIGH_ENTROPY"], withinSameHunk: true, withinLines: 30 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Tests & fixtures", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Token-like value in test/fixture file", description: "A token-like value was added inside a test or fixture file.", risk: "If copied from production, test credentials may still grant real access.", confidenceRationale: "Test fixtures frequently contain dummy tokens, but mistakes do occur.", recommendation: "Confirm this value is fake. Replace with a clearly invalid placeholder if it is not required." }
};

export const W116_SECRET_ECHOED = {
    id: "W116_SECRET_ECHOED",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,sh,bash,zsh,yml,yaml,json}"], excludeGlobs: ["**/dist/**", "**/build/**"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["SECRET", "TOKEN", "PASSWORD", "API_KEY", "PRIVATE_KEY", "CLIENT_SECRET"], withinChars: 120 }, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\becho\\s+\\$\\{?[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*\\}?\\b", "console\\.log\\(\\s*process\\.env\\.[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*\\s*\\)", "print\\(\\s*os\\.environ\\[['\"][A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*['\"]\\]\\s*\\)"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Exposure via logs", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Secret may be printed to logs", description: "A command that may echo or log a secret value was added.", risk: "Secrets written to logs may be captured by CI systems or third-party log processors.", confidenceRationale: "Explicit echo/print of secret-like variables is a common source of accidental exposure.", recommendation: "Avoid printing secrets. Use masked CI variables and ensure sensitive values are not logged." }
};

export const W117_SMTP_CREDENTIALS = {
    id: "W117_SMTP_CREDENTIALS",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,ini,conf}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["smtp", "mail", "MAIL_", "SMTP_", "smtp_password", "smtp_user"], withinChars: 120 }, requireSameHunk: true, requireAssignmentContext: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["KEYWORD_SMTP_CONTEXT", "SECRET_KEYWORD_NEAR_ASSIGNMENT"], withinSameHunk: true, withinLines: 15 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Email providers", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible SMTP credentials committed", description: "SMTP connection credentials were added to the codebase.", risk: "SMTP credentials can be abused to send spam or phishing emails.", confidenceRationale: "SMTP configs often include usernames and passwords but may be placeholders depending on environment.", recommendation: "Move SMTP credentials to a secret manager and rotate them if they are real." }
};

export const W118_REDIS_AUTH = {
    id: "W118_REDIS_AUTH",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,ini,conf,txt}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["redis", "REDIS", "redis_password", "REDIS_PASSWORD", "cache_password"], withinChars: 120 }, requireSameHunk: true, requireAssignmentContext: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["KEYWORD_REDIS_CONTEXT", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 15 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Datastores", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible Redis credential committed", description: "A Redis authentication value was added.", risk: "Redis credentials may allow direct access to cached data or internal services.", confidenceRationale: "Redis auth values are not vendor-prefixed and can be ambiguous without runtime context.", recommendation: "Verify whether this is a real credential and store it securely outside source control if so." }
};

export const W119_SSH_PUBLIC_KEY = {
    id: "W119_SSH_PUBLIC_KEY",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "LOW", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{pub,txt,md}", "**/*"], excludeGlobs: ["**/dist/**", "**/build/**"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, ignoreIfLooksRedacted: false, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\bssh-(rsa|ed25519)\\s+[A-Za-z0-9+/=]{20,}(\\s+[^\\s]+)?\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Keys", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "SSH public key committed", description: "An SSH public key was added to the repository.", risk: "Public keys are not secret, but committing them may unintentionally grant access if deployed automatically.", confidenceRationale: "SSH public keys have a clear format and are not confidential by themselves.", recommendation: "Confirm the key is intended to be public and does not grant unintended access." }
};

export const W120_SECRET_IN_COMMENT = {
    id: "W120_SECRET_IN_COMMENT",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,txt,md}"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["token", "secret", "password", "apikey", "api_key", "client_secret"], withinChars: 120 }, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["LINE_IS_COMMENT", "HIGH_ENTROPY_VALUE_OR_JWT"], withinSameHunk: true, withinLines: 1 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Documentation & comments", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Secret-like value in comment", description: "A comment contains a value that resembles a secret.", risk: "Developers sometimes paste real credentials into comments temporarily, which can expose access.", confidenceRationale: "Comments often include examples, but real secrets do occasionally leak this way.", recommendation: "Ensure comments do not contain real credentials and replace examples with clearly invalid placeholders if it is not required." }
};

export const W121_PRIVATE_KEY_FILENAME = {
    id: "W121_PRIVATE_KEY_FILENAME",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*"], excludeGlobs: ["**/dist/**", "**/build/**"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: false },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: false, ignoreIfLooksRedacted: false, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["FILENAME_LOOKS_PRIVATE_KEY"], withinSameHunk: false } },
    presentation: { group: "Secrets & Credentials", subgroup: "Keys", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "File name suggests private key material", description: "A file name suggests private key material may be present.", risk: "Key files are commonly committed accidentally, which can lead to credential compromise.", confidenceRationale: "Filename alone does not confirm sensitive contents.", recommendation: "Verify the file does not contain sensitive material. If it does, rotate affected keys and remove the file from the repository." }
};

export const W122_PASSWORD_DEFAULT = {
    id: "W122_PASSWORD_DEFAULT",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,ini,conf}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["password", "passwd", "pwd", "defaultPassword", "PASSWORD"], withinChars: 60 }, requireAssignmentContext: true, requireSameHunk: true, ignoreIfLooksRedacted: false, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "VALUE_IS_NON_EMPTY_LITERAL"], withinSameHunk: true, withinLines: 3 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Hardcoded credentials", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Password default value set", description: "A password field was given a default value.", risk: "Default passwords may be deployed unintentionally and can be exploited if not changed.", confidenceRationale: "Default values are sometimes placeholders but are risky when committed to shared configuration.", recommendation: "Avoid default passwords. Use environment-based configuration and enforce rotation/initialization flows." }
};

export const W123_TOKEN_IN_DOCS = {
    id: "W123_TOKEN_IN_DOCS",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{md,rst,txt}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "LOW", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["LINE_LOOKS_DOCS", "HIGH_ENTROPY_VALUE_OR_JWT"], withinSameHunk: true, withinLines: 3 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Documentation & comments", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Token-like value in documentation", description: "Documentation includes a token-like value.", risk: "Documentation may be copied into real deployments, unintentionally exposing credentials.", confidenceRationale: "Docs often include fake examples, but mistakes happen.", recommendation: "Replace tokens with clearly invalid placeholders and avoid documenting real credentials." }
};

export const W124_SECRET_SHARED_ENV = {
    id: "W124_SECRET_SHARED_ENV",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.env", "**/*.env.*", ".env", ".env.*", "**/*.{ini,conf}"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ENV_FILE_MULTIPLE_KEYS_SAME_VALUE"], withinSameHunk: true, withinLines: 50 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Env hygiene", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Secret value appears reused across env variables", description: "A secret value appears reused across multiple environment variables.", risk: "Reusing secrets across contexts can increase blast radius if a single value is compromised.", confidenceRationale: "String reuse is suggestive but not definitive without runtime context.", recommendation: "Use unique secrets per environment and purpose. Rotate if a reused value is sensitive." }
};

export const W125_SECRET_IN_BACKUP_FILE = {
    id: "W125_SECRET_IN_BACKUP_FILE",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{bak,backup,old,tmp,swp}", "**/*~"], scanMode: "BOTH", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { anyOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE_OR_JWT"], withinSameHunk: true, withinLines: 20 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Credentials files", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Potential credential in backup/temporary file", description: "A backup or temporary file contains potential credentials.", risk: "Backup files are often forgotten but remain accessible and can expose real configuration or secrets.", confidenceRationale: "Backup files frequently mirror real configs, but content may still be placeholder text.", recommendation: "Remove backup files from the repository and rotate any real credentials found." }
};

export const W126_SECRET_IN_SAMPLE_CONFIG = {
    id: "W126_SECRET_IN_SAMPLE_CONFIG",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{example,sample,template}", "**/*sample*.*", "**/*example*.*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "LOW", ignoreIfLooksRedacted: false, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { anyOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE_OR_JWT"], withinSameHunk: true, withinLines: 20 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Samples", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Secret-like value in sample configuration", description: "A sample configuration includes secret-like values.", risk: "Sample configs are sometimes copied verbatim into production, risking accidental credential exposure.", confidenceRationale: "Sample configs usually contain placeholders and are not always sensitive.", recommendation: "Ensure sample values are clearly fake and cannot be mistaken for real credentials." }
};

export const W127_BASE64_SECRET_LIKE = {
    id: "W127_BASE64_SECRET_LIKE",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,ini,conf,txt}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["secret", "token", "password", "apikey", "api_key", "private_key", "client_secret"], withinChars: 80 }, requireAssignmentContext: true, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 1 }
    },
    presentation: { group: "Secrets & Credentials", subgroup: "Encodings", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Base64-encoded value near secret-like key", description: "A base64-encoded value was assigned to a secret-like key.", risk: "Base64 is often used to encode secrets, not protect them. If sensitive, this may expose credentials.", confidenceRationale: "Base64 values are common and ambiguous without context.", recommendation: "Confirm whether the value is sensitive. If it is, rotate it and store it securely outside source control." }
};

export const W128_WEBHOOK_URL = {
    id: "W128_WEBHOOK_URL",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env,ini,conf,txt}"], scanMode: "BOTH", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["webhook", "WEBHOOK", "callback", "CALLBACK"], withinChars: 120 }, requireSameHunk: true, ignoreIfLooksRedacted: false, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\bhttps?:\\/\\/[A-Za-z0-9\\-._~%]+(?:\\:[0-9]+)?\\/[A-Za-z0-9\\-._~%\\/]*\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Webhooks", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Webhook URL hardcoded", description: "A webhook URL was hardcoded.", risk: "Webhook URLs sometimes act as shared secrets or can be abused if they trigger sensitive actions.", confidenceRationale: "Webhook URLs lack universal formats and can be non-sensitive, depending on the service.", recommendation: "Move webhook URLs to secure configuration and ensure inbound webhook verification is enabled." }
};

export const W129_SECRET_IN_FRONTEND = {
    id: "W129_SECRET_IN_FRONTEND",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,vue,svelte,html}"], excludeGlobs: ["**/dist/**", "**/build/**", "**/*.min.*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["secret", "token", "password", "apikey", "api_key", "client_secret", "private_key"], withinChars: 80 }, requireAssignmentContext: true, requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["HIGH_ENTROPY_VALUE", "SECRET_KEYWORD_NEAR_ASSIGNMENT"], withinSameHunk: true, withinLines: 8 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Client-side exposure", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Secret-like value in frontend code", description: "A secret-like value was added to frontend code.", risk: "Frontend code is typically public and should never contain secrets. Sensitive values may be exposed to end users or attackers.", confidenceRationale: "High-entropy values assigned to secret-like keys in frontend contexts are rarely intentional and often indicate leakage.", recommendation: "Remove the value and store secrets server-side only, loaded from secure configuration." }
};

export const W130_SECRET_IN_CURL_EXAMPLE = {
    id: "W130_SECRET_IN_CURL_EXAMPLE",
    tier: "TIER_1", kind: "WARN", category: "Secrets & Credentials", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{md,txt,rst,sh,yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "LOW", requireSameHunk: true, ignoreIfLooksRedacted: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            "\\bcurl\\b.*\\b(Authorization:\\s*Bearer\\s+[A-Za-z0-9_\\-\\.]+)",
            "\\bcurl\\b.*\\b(-u\\s+[^\\s]+:[^\\s]+)"
        ],
        negativePatterns: ["REDACTED", "your_token", "example", "<token>", "{TOKEN}"]
    },
    presentation: { group: "Secrets & Credentials", subgroup: "Documentation & examples", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Credentials in curl example", description: "An example curl command includes credentials.", risk: "Examples may be reused without modification, potentially exposing real credentials.", confidenceRationale: "Example commands often contain placeholders, but real tokens are sometimes pasted in.", recommendation: "Replace credentials with clearly invalid placeholders and avoid including real tokens in examples." }
};

export const WARN_SECRETS_RULES = [
    W101_POSSIBLE_SECRET_VAR_ASSIGN, W102_POSSIBLE_SECRET_ENV_ASSIGNMENT, W103_JWT_LIKE_TOKEN, W104_AWS_ACCESS_KEY_ID_UNPAIRED, W105_GCP_API_KEY, W106_TWILIO_SID_PRESENT, W107_NETRC_CREDENTIALS, W108_DOCKER_CONFIG_AUTH, W109_K8S_SECRET_SUSPICIOUS, W110_SUSPICIOUS_CONNECTION_STRING,
    W111_OAUTH_CLIENT_SECRET, W112_BASIC_AUTH_IN_URL, W113_API_KEY_JSON_CONFIG, W114_FIREBASE_SUPABASE_KEY, W115_TOKEN_IN_TEST_FIXTURE, W116_SECRET_ECHOED, W117_SMTP_CREDENTIALS, W118_REDIS_AUTH, W119_SSH_PUBLIC_KEY, W120_SECRET_IN_COMMENT, W121_PRIVATE_KEY_FILENAME, W122_PASSWORD_DEFAULT, W123_TOKEN_IN_DOCS, W124_SECRET_SHARED_ENV, W125_SECRET_IN_BACKUP_FILE, W126_SECRET_IN_SAMPLE_CONFIG, W127_BASE64_SECRET_LIKE, W128_WEBHOOK_URL, W129_SECRET_IN_FRONTEND, W130_SECRET_IN_CURL_EXAMPLE
];
