/**
 * Serverless & Cloud Functions FAIL rules
 */

export const SF001_PUBLIC_FUNCTION_EXPOSURE = {
    id: "SF001_PUBLIC_FUNCTION_EXPOSURE",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: {
        fileGlobs: [
            "**/netlify.toml",
            "**/vercel.json",
            "**/serverless.yml",
            "**/serverless.yaml",
            "**/template.yaml",
            "**/template.yml",
            "**/cloudformation.yml",
            "**/cloudformation.yaml",
            "**/cloudformation.json",
            "**/*.sh",
            "**/Dockerfile"
        ],
        scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            "AuthType:\\s*NONE",
            "AuthorizationType:\\s*NONE",
            "--allow-unauthenticated",
            "allowUnauthenticated:\\s*true"
        ]
    },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Access Control", shortLabel: "Public Function", maxFindingsPerPR: 5, includeInSummary: true },
    explanation: {
        title: "Public function exposure detected",
        description: "Serverless function is explicitly configured to be public or unauthenticated.",
        risk: "Unprotected endpoints can be abused for data exfiltration, unauthorized actions, and denial-of-service, especially if the function has access to internal resources or sensitive data.",
        confidenceRationale: "The detection triggers on explicit 'AuthType: NONE' or similar unequivocal public access flags.",
        recommendation: "Ensure authentication is required for all sensitive functions. If the function must be public, verify it has strict input validation and least-privilege IAM roles."
    }
};

export const SF002_FUNCTION_ENV_PASSES_SECRET_DIRECTLY = {
    id: "SF002_FUNCTION_ENV_PASSES_SECRET_DIRECTLY",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars,env,properties,ini,toml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["environment", "env", "variables", "secret", "token", "key"], withinChars: 520 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CLIENT_SECRET|AWS_SECRET_ACCESS_KEY)\\b\\s*[:=]\\s*['\\\"][^'\\\"]{8,}['\\\"]"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Secrets", shortLabel: "Plaintext secret", maxFindingsPerPR: 2, includeInSummary: true },
    explanation: {
        title: "Plaintext secret assigned in function env config",
        description: "A secret-like env var appears assigned a literal value in source-controlled configuration.",
        risk: "Committed secrets are frequently leaked and can lead to full system compromise.",
        confidenceRationale: "Literal secret-like assignment is explicit and strongly correlated with real secret exposure.",
        recommendation: "Remove committed value, rotate the credential, and load secrets from a managed secret store."
    }
};

export const SF003_VERCEL_NEXT_PUBLIC_ENV_SECRET = {
    id: "SF003_VERCEL_NEXT_PUBLIC_ENV_SECRET",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/vercel.json", "**/*.{env,properties,ini,toml,yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 256, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["NEXT_PUBLIC_", "vercel", "env", "environment"], withinChars: 360 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bNEXT_PUBLIC_[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PRIVATE|ACCESS_KEY|API_KEY)\\b\\s*[:=]"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Client exposure", shortLabel: "Public env secret", maxFindingsPerPR: 3, includeInSummary: true },
    explanation: {
        title: "NEXT_PUBLIC env var name suggests a secret",
        description: "A `NEXT_PUBLIC_...` environment variable name includes secret-like keywords.",
        risk: "NEXT_PUBLIC variables are intended for client-side exposure. Secret-like values can be bundled to browsers and leaked.",
        confidenceRationale: "The `NEXT_PUBLIC_` prefix is explicit; secret keywords are explicit.",
        recommendation: "Do not put secrets in `NEXT_PUBLIC_` variables. Store secrets server-side only."
    }
};

export const SF004_NETLIFY_PUBLIC_ENV_SECRET = {
    id: "SF004_NETLIFY_PUBLIC_ENV_SECRET",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/netlify.toml", "**/*.{env,properties,ini,toml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 256, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["netlify", "environment", "env", "VITE_", "PUBLIC_", "NEXT_PUBLIC_"], withinChars: 420 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(VITE_|PUBLIC_|NEXT_PUBLIC_)[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PRIVATE|ACCESS_KEY|API_KEY)\\b\\s*[:=]"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Client exposure", shortLabel: "Public env secret", maxFindingsPerPR: 3, includeInSummary: true },
    explanation: {
        title: "Public client-exposed env var name suggests a secret",
        description: "An env var prefix commonly used for client exposure includes secret-like keywords.",
        risk: "Client-exposed env vars can leak secrets to browsers, logs, or build artifacts.",
        confidenceRationale: "Prefixes and secret keywords are explicit.",
        recommendation: "Keep secrets server-side only."
    }
};

export const SF005_NETLIFY_FUNCTION_OPEN_PROXY = {
    id: "SF005_NETLIFY_FUNCTION_OPEN_PROXY",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/netlify/functions/**/*.{js,ts}", "**/functions/**/*.{js,ts}", "**/*.{js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["netlify", "handler", "exports.handler", "fetch", "axios", "request", "url"], withinChars: 420 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["SERVERLESS_PROXY_HANDLER_PRESENT", "USER_CONTROLLED_URL_USED", "NO_ALLOWLIST_PRESENT"], withinSameHunk: true, withinLines: 220 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Networking", shortLabel: "Open proxy", maxFindingsPerPR: 1, includeInSummary: true },
    explanation: {
        title: "Serverless function implements an open proxy",
        description: "A function appears to fetch a user-provided URL without an allowlist or destination validation.",
        risk: "Open proxies enable SSRF, internal network probing, and exfiltration.",
        confidenceRationale: "Composite detection of user input flowing into outbound fetch without allowlist.",
        recommendation: "Allowlist destinations and validate URLs defensively."
    }
};

export const SF006_AWS_LAMBDA_DEPRECATED_RUNTIME = {
    id: "SF006_AWS_LAMBDA_DEPRECATED_RUNTIME",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["runtime", "AWS::Lambda::Function", "aws_lambda_function", "lambda"], withinChars: 420 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bruntime\\s*[:=]\\s*['\"]?(nodejs(8\\.10|10\\.x|12\\.x|14\\.x)|python(2\\.7|3\\.6|3\\.7)|ruby2\\.5|dotnetcore2\\.1|go1\\.x)['\"]?\\b", "(?i)\\bRuntime\\s*:\\s*['\"]?(nodejs(8\\.10|10\\.x|12\\.x|14\\.x)|python(2\\.7|3\\.6|3\\.7)|ruby2\\.5|dotnetcore2\\.1|go1\\.x)['\"]?\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Runtimes", shortLabel: "Deprecated runtime", maxFindingsPerPR: 2, includeInSummary: true },
    explanation: {
        title: "Lambda runtime appears deprecated/legacy",
        description: "A Lambda runtime was set to an older runtime that is EOL or lacks security updates.",
        risk: "Deprecated runtimes increase vulnerability exposure.",
        confidenceRationale: "Explicit runtime strings.",
        recommendation: "Upgrade to a supported runtime."
    }
};

export const SF007_GCP_FUNCTIONS_DEPRECATED_RUNTIME = {
    id: "SF007_GCP_FUNCTIONS_DEPRECATED_RUNTIME",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["cloudfunctions", "google_cloudfunctions", "runtime", "gcp"], withinChars: 520 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bruntime\\s*[:=]\\s*['\"]?(nodejs(10|12|14)|python(2\\.7|3\\.7)|go(1\\.13|1\\.16)|ruby(2\\.5|2\\.7))['\"]?\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Runtimes", shortLabel: "Deprecated runtime", maxFindingsPerPR: 2, includeInSummary: true },
    explanation: {
        title: "GCP Cloud Functions runtime appears deprecated/legacy",
        description: "A Cloud Functions runtime was set to an older runtime commonly treated as legacy/EOL.",
        risk: "Legacy runtimes reduce patch availability.",
        confidenceRationale: "Explicit runtime identifiers.",
        recommendation: "Move to supported runtimes."
    }
};

export const SF008_FUNCTION_DEBUG_ENABLED = {
    id: "SF008_FUNCTION_DEBUG_ENABLED",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars,env,properties,js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["NODE_OPTIONS", "inspect", "debug", "DEBUG=", "trace", "function", "lambda"], withinChars: 420 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bNODE_OPTIONS\\b\\s*[:=]\\s*['\\\"]?[^\\n'\\\"]*--inspect(-brk)?\\b", "(?i)\\b--inspect(-brk)?\\b", "(?i)\\bDEBUG\\s*[:=]\\s*true\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Hardening", shortLabel: "Debug enabled", maxFindingsPerPR: 2, includeInSummary: true },
    explanation: {
        title: "Debugger or verbose debug mode enabled",
        description: "Configuration suggests debugger flags or verbose debug mode are enabled.",
        risk: "Debug modes can leak sensitive runtime details and expand attack surface.",
        confidenceRationale: "Explicit debugger flags.",
        recommendation: "Disable debugger flags and verbose debug modes in production."
    }
};

export const SF009_FUNCTION_WRITABLE_SERVED = {
    id: "SF010_FUNCTION_WRITABLE_SERVED",
    tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["WRITABLE_TMP_OR_WORKDIR_USED", "SERVED_STATIC_FROM_PATH_PRESENT"], withinSameHunk: true, withinLines: 220 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "File handling", shortLabel: "Writable served", maxFindingsPerPR: 1, includeInSummary: true },
    explanation: {
        title: "Writable temp/workdir served as static content",
        description: "Code suggests writable paths could be served as static files.",
        risk: "Enables data exposure or content injection.",
        confidenceRationale: "Composite detection of writable path and static serving wiring.",
        recommendation: "Never serve writable temp directories."
    }
};

export const FAIL_SERVERLESS_RULES = [
    SF001_PUBLIC_FUNCTION_EXPOSURE,
    SF002_FUNCTION_ENV_PASSES_SECRET_DIRECTLY,
    SF003_VERCEL_NEXT_PUBLIC_ENV_SECRET,
    SF004_NETLIFY_PUBLIC_ENV_SECRET,
    SF005_NETLIFY_FUNCTION_OPEN_PROXY,
    SF006_AWS_LAMBDA_DEPRECATED_RUNTIME,
    SF007_GCP_FUNCTIONS_DEPRECATED_RUNTIME,
    SF008_FUNCTION_DEBUG_ENABLED,
    SF009_FUNCTION_WRITABLE_SERVED
];
