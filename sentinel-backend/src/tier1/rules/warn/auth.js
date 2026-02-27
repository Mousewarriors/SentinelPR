export const A201_WEAK_SESSION_COOKIE = {
    id: "A201_WEAK_SESSION_COOKIE",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], excludeGlobs: ["**/dist/**", "**/build/**"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["cookie", "session", "setCookie", "Set-Cookie"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["COOKIE_SET_PRESENT", "COOKIE_FLAGS_MISSING_OR_WEAK"], withinSameHunk: true, withinLines: 20 } },
    presentation: { group: "Auth & Session", subgroup: "Cookies", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Session cookie may be missing security attributes", description: "Session cookies may be missing secure attributes.", risk: "Cookies without proper flags are more vulnerable to theft or misuse.", confidenceRationale: "Cookie-related code was modified, but the analysis cannot confirm runtime behavior or environment defaults.", recommendation: "Ensure secure, httpOnly, and appropriate sameSite attributes are set for session cookies." }
};

export const A202_JWT_VERIFICATION_RELAXED = {
    id: "A202_JWT_VERIFICATION_RELAXED",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["jwt", "jsonwebtoken", "verify", "decode", "alg", "none"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { anyOf: ["JWT_VERIFY_OPTIONS_WEAK", "JWT_ALG_NONE_ALLOWED"], withinSameHunk: true, withinLines: 25 } },
    presentation: { group: "Auth & Session", subgroup: "JWT", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "JWT verification may be weakened", description: "JWT verification options appear to be relaxed.", risk: "Relaxed verification can allow token forgery or replay.", confidenceRationale: "JWT libraries expose many options that are safe in tests but risky in production; static analysis cannot confirm full configuration.", recommendation: "Review JWT verification settings and ensure signature and issuer/audience checks are enforced." }
};

export const A203_MISSING_AUTH_MIDDLEWARE = {
    id: "A203_MISSING_AUTH_MIDDLEWARE",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ROUTE_DEFINITION_PRESENT", "AUTH_MIDDLEWARE_NOT_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 40 } },
    presentation: { group: "Auth & Session", subgroup: "Routes", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Route may be missing authentication", description: "A route definition may be missing authentication middleware.", risk: "Unauthenticated routes can expose sensitive functionality.", confidenceRationale: "Static analysis cannot reliably determine route protection across frameworks and composition patterns.", recommendation: "Confirm the route is intentionally public, or add authentication/authorization middleware as appropriate." }
};

export const A204_CORS_PERMISSIVE = {
    id: "A204_CORS_PERMISSIVE",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["cors", "CORS", "Access-Control-Allow-Origin", "credentials"], withinChars: 140 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { anyOf: ["CORS_WILDCARD", "CORS_WILDCARD_WITH_CREDENTIALS"], withinSameHunk: true, withinLines: 25 } },
    presentation: { group: "Auth & Session", subgroup: "CORS", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "CORS configuration may be overly permissive", description: "CORS configuration appears overly permissive.", risk: "Permissive CORS may allow unauthorized cross-origin access or data exposure.", confidenceRationale: "Static configs can’t always distinguish dev vs prod settings, but wildcard patterns are frequently risky.", recommendation: "Restrict allowed origins and review whether credentials are necessary for cross-origin requests." }
};

export const A205_DEBUG_AUTH_BYPASS = {
    id: "A205_DEBUG_AUTH_BYPASS",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,env,yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(DISABLE_AUTH|AUTH_BYPASS|BYPASS_AUTH|SKIP_AUTH|NO_AUTH)\\b\\s*(=|:)\\s*(true|1|yes)\\b", "(?i)\\bif\\s*\\(\\s*(DEBUG|DEV|TEST)\\s*\\)\\s*\\{[^}]*\\b(bypass|skip)\\b[^}]*\\}"] },
    presentation: { group: "Auth & Session", subgroup: "Bypasses", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Debug authentication bypass may be enabled", description: "A debug or development flag may bypass authentication.", risk: "Debug bypasses accidentally deployed to production can expose the entire application.", confidenceRationale: "Explicit bypass flags and common bypass patterns are deterministic indicators of reduced auth enforcement.", recommendation: "Ensure debug bypasses are disabled in production and protected by strict environment guards." }
};

export const A206_LONG_LIVED_TOKENS = {
    id: "A206_LONG_LIVED_TOKENS",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml,json,env}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["expires", "expiry", "ttl", "token", "session", "maxAge", "exp"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\b(maxAge|ttl|expiresIn|expiry|expiration)\\b\\s*[:=]\\s*(\"|')?([0-9]{7,}|[0-9]+\\s*(d|day|days|w|week|weeks))\\b"] },
    presentation: { group: "Auth & Session", subgroup: "Token lifetime", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Token lifetime may be long", description: "Authentication tokens appear to have long expiration times.", risk: "Long-lived tokens increase impact if compromised.", confidenceRationale: "Expiration values vary by use case and environment; this is a heuristic signal.", recommendation: "Review token lifetimes and reduce them where possible. Prefer refresh-token flows and revocation support." }
};

export const A207_WEAK_PASSWORD_HASHING = {
    id: "A207_WEAK_PASSWORD_HASHING",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(md5|sha1)\\b\\s*\\(", "(?i)\\b(password)\\b.*\\b(md5|sha1)\\b"], negativePatterns: ["checksum", "etag", "integrity"] },
    presentation: { group: "Auth & Session", subgroup: "Password hashing", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Password hashing may be weak", description: "Password hashing configuration may be weak.", risk: "Weak hashing increases the risk of credential compromise if password hashes are leaked.", confidenceRationale: "Weak algorithms are easy to detect, but static analysis cannot confirm the value is a password in all cases.", recommendation: "Use modern password hashing (bcrypt, scrypt, Argon2) with appropriate parameters and unique salts." }
};

export const A208_AUTH_STATE_CLIENT_SIDE = {
    id: "A208_AUTH_STATE_CLIENT_SIDE",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], excludeGlobs: ["**/dist/**", "**/build/**"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(localStorage|sessionStorage)\\.(setItem|getItem)\\(.*(token|auth|jwt|session)", "(?i)\\bdocument\\.cookie\\s*=.*(token|auth|jwt|session)"] },
    presentation: { group: "Auth & Session", subgroup: "Client-side auth state", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Auth state may be stored client-side", description: "Authentication state may be stored client-side.", risk: "Client-side auth state can be tampered with or exposed via XSS, increasing account takeover risk.", confidenceRationale: "Storage APIs are detectable, but correct usage depends on surrounding controls and threat model.", recommendation: "Prefer httpOnly secure cookies for session tokens and ensure server-side verification is enforced." }
};

export const A209_PASSWORD_RESET_EXPOSED = {
    id: "A209_PASSWORD_RESET_EXPOSED",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["reset", "password", "token"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { anyOf: ["RESET_TOKEN_LOGGED", "RESET_TOKEN_RETURNED_IN_RESPONSE"], withinSameHunk: true, withinLines: 30 } },
    presentation: { group: "Auth & Session", subgroup: "Password reset", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Password reset token handling may expose sensitive data", description: "Password reset token handling may expose sensitive data.", risk: "Exposed reset tokens can allow account takeover.", confidenceRationale: "Reset flows vary and static analysis cannot confirm full context, but logging/returning tokens is frequently risky.", recommendation: "Ensure reset tokens are short-lived, single-use, not logged, and not returned to clients unnecessarily." }
};

export const A210_AUTH_LOGGING_SENSITIVE = {
    id: "A210_AUTH_LOGGING_SENSITIVE",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["auth", "login", "token", "password", "session", "bearer"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(console\\.log|logger\\.(info|debug|warn)|print)\\b.*\\b(authorization|bearer|token|password|session)\\b"] },
    presentation: { group: "Auth & Session", subgroup: "Logging", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Auth-related logs may include sensitive data", description: "Authentication logs may include sensitive user identifiers or tokens.", risk: "Logs may leak personal or authentication-related data, increasing the impact of log access or breaches.", confidenceRationale: "Logging calls are detectable, but static analysis cannot confirm what values are actually included at runtime.", recommendation: "Avoid logging tokens, passwords, or Authorization headers. Ensure log redaction and masking are applied." }
};

export const A211_INSECURE_PASSWORD_RESET_LINK = {
    id: "A211_INSECURE_PASSWORD_RESET_LINK",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["reset", "password", "token", "link"], withinChars: 140 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { anyOf: ["RESET_LINK_HTTP", "RESET_LINK_TOKEN_WEAK_CONTEXT"], withinSameHunk: true, withinLines: 40 } },
    presentation: { group: "Auth & Session", subgroup: "Password reset", shortLabel: "Reset link", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Password reset link may be insecure", description: "Password reset link generation or handling may be insecure.", risk: "Weak reset links can enable account takeover if tokens are guessable, logged, or transmitted insecurely.", confidenceRationale: "Reset flows vary widely; this warning is heuristic and highlights patterns that often cause exposure.", recommendation: "Ensure reset tokens are cryptographically random, short-lived, transmitted only over HTTPS, and never logged." }
};

export const A212_OPEN_REDIRECT_PARAM = {
    id: "A212_OPEN_REDIRECT_PARAM",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["redirect", "returnTo", "next", "callback", "url"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["REDIRECT_PARAM_PRESENT", "REDIRECT_TARGET_FROM_REQUEST"], withinSameHunk: true, withinLines: 30 } },
    presentation: { group: "Auth & Session", subgroup: "Redirects", shortLabel: "Redirect", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Redirect target may be user-controlled", description: "A redirect target appears to be derived from a request parameter.", risk: "Open redirects can be used for phishing, token leakage, or redirect-based attacks.", confidenceRationale: "Static analysis can detect redirect-like patterns but cannot confirm validation or allowlists.", recommendation: "Validate redirect targets against an allowlist of known paths/domains and avoid redirecting to arbitrary URLs." }
};

export const A213_AUTHZ_CHECK_MAY_BE_MISSING = {
    id: "A213_AUTHZ_CHECK_MAY_BE_MISSING",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["admin", "role", "permission", "authorize", "authz"], withinChars: 160 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["SENSITIVE_ACTION_KEYWORDS", "NO_AUTHZ_KEYWORDS_NEARBY"], withinSameHunk: true, withinLines: 60 } },
    presentation: { group: "Auth & Session", subgroup: "Authorization", shortLabel: "Authz", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Authorization check may be missing", description: "A potentially sensitive operation was added without obvious authorization checks nearby.", risk: "Missing authorization can allow users to access or modify resources they should not be able to.", confidenceRationale: "Authorization is framework- and architecture-dependent; this is a conservative heuristic and may be a false positive.", recommendation: "Confirm that authorization is enforced for this operation (policy/role checks, ownership checks, or centralized middleware)." }
};

export const A214_ROLE_ADMIN_STRING_CHECK = {
    id: "A214_ROLE_ADMIN_STRING_CHECK",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["role", "admin", "isAdmin", "permission"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(role|permission)\\b.*==\\s*['\"]admin['\"]", "(?i)\\bisAdmin\\b\\s*==\\s*(true|1)\\b"] },
    presentation: { group: "Auth & Session", subgroup: "Authorization", shortLabel: "Role check", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Simple role check detected", description: "Authorization appears to rely on a simple string/boolean role check.", risk: "Naive role checks can be bypassed if role values are user-controlled or not centrally enforced.", confidenceRationale: "This pattern is detectable but may be safe if role data is trusted and checked consistently elsewhere.", recommendation: "Prefer centralized authorization policies and ensure role claims are server-verified and not user-controlled." }
};

export const A215_SAMESITE_NONE_WITHOUT_SECURE_HEURISTIC = {
    id: "A215_SAMESITE_NONE_WITHOUT_SECURE_HEURISTIC",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["sameSite", "samesite", "secure", "cookie"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["COOKIE_SAMESITE_NONE_PRESENT", "COOKIE_SECURE_NOT_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 20 } },
    presentation: { group: "Auth & Session", subgroup: "Cookies", shortLabel: "SameSite", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "SameSite=None without Secure may be risky", description: "A cookie was configured with SameSite=None without an obvious Secure flag nearby.", risk: "Cookies with SameSite=None should generally require Secure to reduce exposure to cross-site attacks.", confidenceRationale: "Static analysis cannot always see full cookie configuration; this warning highlights a common misconfiguration.", recommendation: "Ensure cookies using SameSite=None are marked Secure and review cross-site cookie requirements." }
};

export const A216_COOKIE_DOMAIN_WILDCARD = {
    id: "A216_COOKIE_DOMAIN_WILDCARD",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["domain", "cookie"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bdomain\\b\\s*[:=]\\s*['\"]\\.[^'\"]+['\"]"] },
    presentation: { group: "Auth & Session", subgroup: "Cookies", shortLabel: "Cookie domain", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Cookie domain scope may be broad", description: "A cookie domain appears to be set to a broad scope (e.g., .example.com).", risk: "Broad domain cookies may be accessible by more subdomains than intended, increasing attack surface.", confidenceRationale: "The domain attribute is detectable, but correctness depends on the organization’s domain and architecture.", recommendation: "Scope cookies to the narrowest domain possible and avoid broad domain cookies unless required." }
};

export const A217_SESSION_FIXATION_RISK = {
    id: "A217_SESSION_FIXATION_RISK",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["login", "session", "regenerate", "rotate", "cookie"], withinChars: 160 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["LOGIN_FLOW_KEYWORDS", "NO_SESSION_REGEN_KEYWORDS"], withinSameHunk: true, withinLines: 80 } },
    presentation: { group: "Auth & Session", subgroup: "Sessions", shortLabel: "Session rotate", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Session rotation may be missing on login", description: "Login-related code was modified without obvious session rotation/regeneration nearby.", risk: "Not rotating sessions on login can increase exposure to session fixation attacks.", confidenceRationale: "Session handling is framework-specific; this is a heuristic signal and may not apply if rotation is centralized.", recommendation: "Confirm sessions are rotated/regenerated on authentication and privilege changes." }
};

export const A218_PASSWORD_POLICY_WEAK = {
    id: "A218_PASSWORD_POLICY_WEAK",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,json,yml,yaml,env}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["password", "minLength", "complexity", "policy", "regex"], withinChars: 140 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)min(length)?\\s*[:=]\\s*(0|1|2|3|4|5|6|7)\\b"] },
    presentation: { group: "Auth & Session", subgroup: "Password policy", shortLabel: "Pwd policy", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Password policy may be weak", description: "Password validation configuration appears to allow short or weak passwords.", risk: "Weak password policies increase the risk of credential stuffing and brute-force attacks succeeding.", confidenceRationale: "Policy settings vary and may be overridden elsewhere; this is a heuristic warning.", recommendation: "Review password policy requirements and align with your threat model and compliance needs." }
};

export const A219_MFA_DISABLED_FLAG = {
    id: "A219_MFA_DISABLED_FLAG",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{env,yml,yaml,json,js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 256, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(DISABLE_MFA|MFA_DISABLED|ENABLE_MFA)\\b\\s*(=|:)\\s*(true|false|0|1)\\b"] },
    presentation: { group: "Auth & Session", subgroup: "MFA", shortLabel: "MFA", maxFindingsPerPR: 1, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "MFA configuration changed", description: "Multi-factor authentication configuration was modified.", risk: "Disabling or weakening MFA can significantly increase the likelihood of account compromise.", confidenceRationale: "Explicit MFA toggle flags are deterministic, but impact depends on environment and rollout logic.", recommendation: "Confirm MFA remains enforced for high-risk accounts and production environments." }
};

export const A220_OAUTH_STATE_MISSING = {
    id: "A220_OAUTH_STATE_MISSING",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["oauth", "authorize", "callback", "state"], withinChars: 180 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["OAUTH_AUTHORIZE_FLOW", "OAUTH_STATE_NOT_PRESENT"], withinSameHunk: true, withinLines: 80 } },
    presentation: { group: "Auth & Session", subgroup: "OAuth", shortLabel: "OAuth state", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "OAuth state parameter may be missing", description: "OAuth authorization flow code was added without an obvious state parameter check.", risk: "Missing state validation can enable CSRF attacks against OAuth flows, leading to account linking or login confusion.", confidenceRationale: "OAuth implementations differ; static analysis cannot confirm whether state is handled elsewhere.", recommendation: "Confirm state is generated, stored, and validated for OAuth authorization and callback handling." }
};

export const A221_JWT_DECODE_USED_FOR_AUTH = {
    id: "A221_JWT_DECODE_USED_FOR_AUTH",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["jwt", "decode", "authorization", "bearer", "token"], withinChars: 140 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(jwt\\.decode|jsonwebtoken\\.decode|decode\\(token\\))\\b"] },
    presentation: { group: "Auth & Session", subgroup: "JWT", shortLabel: "JWT decode", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "JWT decode used where verification may be expected", description: "A JWT decode operation was added in an authentication context.", risk: "Decoding a JWT without verifying its signature can allow attackers to forge tokens and bypass authentication.", confidenceRationale: "Decode APIs are easy to detect, but static analysis cannot confirm whether verification happens elsewhere.", recommendation: "Ensure JWTs are verified (signature + issuer/audience + expiration) before trusting claims." }
};

export const A222_IDOR_STYLE_PARAM = {
    id: "A222_IDOR_STYLE_PARAM",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["userId", "accountId", "orgId", "tenantId", "id"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(req\\.(params|query|body)\\.(userId|accountId|orgId|tenantId|id))\\b"] },
    presentation: { group: "Auth & Session", subgroup: "Authorization", shortLabel: "ID param", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "User-controlled identifier used", description: "A user-controlled identifier parameter was introduced.", risk: "If authorization checks are missing, this can lead to insecure direct object reference (IDOR) issues.", confidenceRationale: "Identifiers are common and often safe; static analysis cannot confirm authorization enforcement.", recommendation: "Ensure access checks validate ownership/tenant membership for any resource referenced by user-controlled IDs." }
};

export const A223_SENSITIVE_ENDPOINT_PUBLIC_ROUTE = {
    id: "A223_SENSITIVE_ENDPOINT_PUBLIC_ROUTE",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["admin", "billing", "invoice", "payout", "token", "apikey", "webhook"], withinChars: 180 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ROUTE_DEFINITION_PRESENT", "SENSITIVE_ROUTE_KEYWORDS", "AUTH_MIDDLEWARE_NOT_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 60 } },
    presentation: { group: "Auth & Session", subgroup: "Routes", shortLabel: "Sensitive route", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Sensitive route may be public", description: "A route with sensitive keywords was introduced without obvious auth middleware nearby.", risk: "Public access to sensitive endpoints can lead to data exposure or privilege escalation.", confidenceRationale: "Routing and auth are framework-dependent; this is a conservative heuristic.", recommendation: "Confirm the endpoint is protected by authentication and authorization checks appropriate to its sensitivity." }
};

export const A224_RATE_LIMIT_MISSING_AUTH_ENDPOINT = {
    id: "A224_RATE_LIMIT_MISSING_AUTH_ENDPOINT",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["login", "signin", "password", "reset", "otp", "mfa"], withinChars: 200 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["AUTH_ENDPOINT_KEYWORDS", "NO_RATE_LIMIT_KEYWORDS_NEARBY"], withinSameHunk: true, withinLines: 80 } },
    presentation: { group: "Auth & Session", subgroup: "Abuse protection", shortLabel: "Rate limit", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Rate limiting may be missing on auth endpoint", description: "An authentication-related endpoint was modified without obvious rate limiting nearby.", risk: "Missing rate limits can enable brute-force, credential stuffing, or OTP abuse.", confidenceRationale: "Rate limiting is often applied globally; static analysis cannot confirm coverage for this endpoint.", recommendation: "Confirm rate limiting and abuse protection are applied to authentication and password reset endpoints." }
};

export const A225_PASSWORD_RESET_TOKEN_IN_URL_LOG = {
    id: "A225_PASSWORD_RESET_TOKEN_IN_URL_LOG",
    tier: "TIER_1", kind: "WARN", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["reset", "token", "password", "url"], withinChars: 160 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)(console\\.log|logger\\.(info|debug|warn)|print)\\(.*(reset|token).*\\)", "(?i)\\b(reset|password).*token=.*\\b"] },
    presentation: { group: "Auth & Session", subgroup: "Password reset", shortLabel: "Reset token", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Reset token may be exposed", description: "Password reset token values may be logged or embedded in URLs.", risk: "If reset tokens are exposed, attackers may be able to take over accounts.", confidenceRationale: "Logging or embedding token-like parameters is detectable, but full context may vary by framework.", recommendation: "Avoid logging tokens and ensure reset tokens are short-lived, single-use, and transmitted only over HTTPS." }
};

export const WARN_AUTH_RULES = [
    A201_WEAK_SESSION_COOKIE, A202_JWT_VERIFICATION_RELAXED, A203_MISSING_AUTH_MIDDLEWARE, A204_CORS_PERMISSIVE, A205_DEBUG_AUTH_BYPASS, A206_LONG_LIVED_TOKENS, A207_WEAK_PASSWORD_HASHING, A208_AUTH_STATE_CLIENT_SIDE, A209_PASSWORD_RESET_EXPOSED, A210_AUTH_LOGGING_SENSITIVE,
    A211_INSECURE_PASSWORD_RESET_LINK, A212_OPEN_REDIRECT_PARAM, A213_AUTHZ_CHECK_MAY_BE_MISSING, A214_ROLE_ADMIN_STRING_CHECK, A215_SAMESITE_NONE_WITHOUT_SECURE_HEURISTIC, A216_COOKIE_DOMAIN_WILDCARD, A217_SESSION_FIXATION_RISK, A218_PASSWORD_POLICY_WEAK, A219_MFA_DISABLED_FLAG, A220_OAUTH_STATE_MISSING, A221_JWT_DECODE_USED_FOR_AUTH, A222_IDOR_STYLE_PARAM, A223_SENSITIVE_ENDPOINT_PUBLIC_ROUTE, A224_RATE_LIMIT_MISSING_AUTH_ENDPOINT, A225_PASSWORD_RESET_TOKEN_IN_URL_LOG
];
