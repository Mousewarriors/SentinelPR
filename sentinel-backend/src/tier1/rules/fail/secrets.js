/**
 * Secrets & Credentials FAIL rules
 */

export const FS001_POSSIBLE_SECRET_ASSIGN = {
    id: "FS001_POSSIBLE_SECRET_ASSIGN",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}", "**/*.{env,ini,conf,json,yml,yaml,txt}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["secret", "token", "password", "apikey", "private_key"], withinChars: 80 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 5 } },
    presentation: { group: "Secrets & Credentials", subgroup: "High-confidence secrets", includeInSummary: true },
    explanation: {
        title: "Possible secret committed",
        description: "A high-entropy value was added near a secret-like variable or configuration key.",
        risk: "Real credentials in source control allow unauthorized access.",
        confidenceRationale: "High-entropy values near secret keywords are high-confidence indicators of leakage.",
        recommendation: "Rotate the credential and move it to a secret manager."
    }
};

export const FS002_POSSIBLE_SECRET_ENV = {
    id: "FS002_POSSIBLE_SECRET_ENV",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.env", "**/*.env.*", ".env", ".env.*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM" },
    detection: { type: "CONFIG_KV", kv: { keyPatterns: ["(?i)^(\\s*)([A-Z0-9_]*?(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*)\\s*="], valuePatterns: ["^.{16,}$"] } },
    presentation: { group: "Secrets & Credentials", subgroup: "Env secrets", includeInSummary: true },
    explanation: {
        title: "Credential detected in environment file",
        description: "A secret-like environment variable was added to an env file.",
        risk: "Exposes production access to anyone with repo access.",
        confidenceRationale: "Explicit key naming in sensitive files.",
        recommendation: "Use a secret manager or deployment-level env vars."
    }
};

export const FS003_AWS_ACCESS_KEY = {
    id: "FS003_AWS_ACCESS_KEY",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH" },
    detection: { type: "REGEX", patterns: ["\\b(AKIA|ASIA)[0-9A-Z]{16}\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Cloud credentials", includeInSummary: true },
    explanation: {
        title: "AWS Access Key ID committed",
        description: "An AWS access key ID was detected.",
        risk: "Indicates cloud credentials may be hardcoded or leaked.",
        confidenceRationale: "AWS access keys have a fixed, highly recognizable prefix.",
        recommendation: "Rotate the key in AWS IAM immediately."
    }
};

export const FS004_NETRC_CREDENTIALS = {
    id: "FS004_NETRC_CREDENTIALS",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/.netrc", ".netrc"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW" },
    detection: { type: "REGEX", patterns: ["(?i)\\bmachine\\b.+\\blogin\\b.+\\bpassword\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Credentials files", includeInSummary: true },
    explanation: {
        title: "Git/Netrc credentials committed",
        description: "A .netrc file containing login/password pairs was added.",
        risk: "Grants direct access to remote services.",
        confidenceRationale: "Explicit credential storage format.",
        recommendation: "Remove the file and use CI secrets."
    }
};

export const FS005_BASIC_AUTH_IN_URL = {
    id: "FS005_BASIC_AUTH_IN_URL",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", prodHeuristics: { requireNonLocalHost: true } },
    detection: { type: "REGEX", patterns: ["\\b[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/[^\\s:@/]+:[^\\s@/]+@[^\\s/]+\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Exposure", includeInSummary: true },
    explanation: {
        title: "Credentials embedded in URL",
        description: "A URL containing username:password was detected.",
        risk: "Credentials in URLs are leaked via logs and browser history.",
        confidenceRationale: "Unambiguous credential pattern.",
        recommendation: "Remove credentials from URLs."
    }
};

export const FS006_SECRET_ECHOED = {
    id: "FS006_SECRET_ECHOED",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{sh,bash,zsh,js,ts,py,rb,php,yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", requireKeywordProximity: { keywords: ["SECRET", "TOKEN", "PASSWORD"], withinChars: 120 } },
    detection: { type: "REGEX", patterns: ["\\becho\\s+\\$\\{?[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*\\}?\\b", "console\\.log\\(\\s*process\\.env\\.[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*\\s*\\)"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Exposure", includeInSummary: true },
    explanation: {
        title: "Secret potential exposure in logs",
        description: "A command that prints a secret-like environment variable was added.",
        risk: "Secrets leaked to CI logs are wide open to compromise.",
        confidenceRationale: "Explicit print/echo of secret-named variables.",
        recommendation: "Avoid printing secrets."
    }
};

export const FS007_GCP_API_KEY = {
    id: "FS007_GCP_API_KEY",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "MEDIUM" },
    detection: { type: "REGEX", patterns: ["\\bAIza[0-9A-Za-z\\-_]{30,}\\b"] },
    presentation: { group: "Secrets & Credentials", subgroup: "Cloud credentials", includeInSummary: true },
    explanation: { title: "Possible Google API key committed", description: "A value matching Google API key format was detected.", risk: "Exposes Google Cloud services.", recommendation: "Confirm validity and rotate if needed." }
};

export const FS008_DOCKER_AUTH = {
    id: "FS008_DOCKER_AUTH",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/config.json", "**/.docker/config.json"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    detection: { type: "REGEX", patterns: ["\"auth\"\\s*:\\s*\"[A-Za-z0-9+/=]{20,}\""] },
    presentation: { group: "Secrets & Credentials", subgroup: "Credentials files", includeInSummary: true },
    explanation: { title: "Docker registry credentials detected", description: "A Docker config entry with auth field was added.", risk: "Allows unauthorized access to private images.", recommendation: "Do not commit Docker config files with auth." }
};

export const FS009_OAUTH_CLIENT_SECRET = {
    id: "FS009_OAUTH_CLIENT_SECRET",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { requireKeywordProximity: { keywords: ["client_secret", "CLIENT_SECRET"], withinChars: 80 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["SECRET_KEYWORD_NEAR_ASSIGNMENT", "HIGH_ENTROPY_VALUE"], withinSameHunk: true, withinLines: 5 } },
    presentation: { group: "Secrets & Credentials", subgroup: "OAuth", includeInSummary: true },
    explanation: { title: "OAuth client secret committed", description: "A potential OAuth client secret was added.", risk: "Allows app impersonation.", recommendation: "Move to a secret manager." }
};

export const FS010_SMTP_CREDENTIALS = {
    id: "FS010_SMTP_CREDENTIALS",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { requireKeywordProximity: { keywords: ["smtp", "SMTP_PASSWORD"], withinChars: 120 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["KEYWORD_SMTP_CONTEXT", "SECRET_KEYWORD_NEAR_ASSIGNMENT"], withinSameHunk: true, withinLines: 15 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Email", includeInSummary: true },
    explanation: { title: "SMTP credentials committed", description: "SMTP login details were added.", risk: "Abuse for spam/phishing.", recommendation: "Move to a secret manager." }
};

export const FS011_FRONTEND_SECRET = {
    id: "FS011_FRONTEND_SECRET",
    tier: "TIER_1", kind: "FAIL", category: "Secrets & Credentials", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,vue,svelte,html}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { requireKeywordProximity: { keywords: ["secret", "token", "apikey"], withinChars: 80 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["HIGH_ENTROPY_VALUE", "SECRET_KEYWORD_NEAR_ASSIGNMENT"], withinSameHunk: true, withinLines: 8 } },
    presentation: { group: "Secrets & Credentials", subgroup: "Client-side exposure", includeInSummary: true },
    explanation: { title: "Secret in frontend code", description: "A secret-like value was added to frontend code.", risk: "Frontend secrets are effectively public.", recommendation: "Remove and store server-side only." }
};

export const FAIL_SECRETS_RULES = [
    FS001_POSSIBLE_SECRET_ASSIGN,
    FS002_POSSIBLE_SECRET_ENV,
    FS003_AWS_ACCESS_KEY,
    FS004_NETRC_CREDENTIALS,
    FS005_BASIC_AUTH_IN_URL,
    FS006_SECRET_ECHOED,
    FS007_GCP_API_KEY,
    FS008_DOCKER_AUTH,
    FS009_OAUTH_CLIENT_SECRET,
    FS010_SMTP_CREDENTIALS,
    FS011_FRONTEND_SECRET
];
