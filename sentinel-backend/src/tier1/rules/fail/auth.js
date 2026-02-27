/**
 * Auth & Session FAIL rules
 */

// Atomic patterns for IDOR composite rules
export const IDOR_PARAMETER_IN_URL = { type: "REGEX", patterns: ["(?i)/(user|account|order|invoice|profile|file|document)(s|)/[:{][a-zA-Z0-9_-]+[}:]"] };
export const IDOR_DB_LOOKUP_BY_ID = { type: "REGEX", patterns: ["(?i)\\.(findOne|findByPk|get|find|lookup)\\s*\\(\\s*([^,}]*id[^,}]*)\\s*\\)"] };
export const IDOR_OWNERSHIP_CHECK_NOT_PRESENT = { type: "REGEX", patterns: ["^.*$"], negativePatterns: ["(?i)(owner|creator|userId|belongsTo|authorized|checkPermission|session\\.user\\.id)"] };

export const FA001_DEBUG_AUTH_BYPASS = {
    id: "FA001_DEBUG_AUTH_BYPASS",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(DISABLE_AUTH|AUTH_BYPASS|BYPASS_AUTH|SKIP_AUTH|NO_AUTH)\\b\\s*(=|:)\\s*(true|1|yes)\\b"] },
    presentation: { group: "Auth & Session", subgroup: "Bypasses", includeInSummary: true },
    explanation: {
        title: "Auth bypass flag enabled",
        description: "A flag that explicitly disables authentication was added.",
        risk: "Accidental deployment of auth bypasses leads to total compromise.",
        confidenceRationale: "Explicit 'DISABLE_AUTH' style keywords.",
        recommendation: "Remove auth bypass flags."
    }
};

export const FA002_WEAK_PASSWORD_HASHING = {
    id: "FA002_WEAK_PASSWORD_HASHING",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(password)\\b.*\\b(md5|sha1)\\b"], negativePatterns: ["checksum", "etag"] },
    presentation: { group: "Auth & Session", subgroup: "Cryptography", includeInSummary: true },
    explanation: {
        title: "Weak algorithm for passwords",
        description: "MD5 or SHA1 appears used for password processing.",
        risk: "Weak hashes are easily cracked if leaked.",
        confidenceRationale: "Association of 'password' keyword with weak hash algorithms.",
        recommendation: "Use bcrypt, Argon2, or scrypt."
    }
};

export const FA003_MFA_DISABLED_FLAG = {
    id: "FA003_MFA_DISABLED_FLAG",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{env,yml,yaml,json,js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW" },
    detection: { type: "REGEX", patterns: ["(?i)\\b(DISABLE_MFA|MFA_DISABLED)\\b\\s*(=|:)\\s*(true|1|yes)\\b"] },
    presentation: { group: "Auth & Session", subgroup: "MFA", includeInSummary: true },
    explanation: {
        title: "MFA disability flag detected",
        description: "A configuration explicitly disabling MFA was added.",
        risk: "Significantly increases account takeover risk.",
        confidenceRationale: "Explicit MFA toggle names.",
        recommendation: "Enforce MFA for all production environments."
    }
};

export const FA004_JWT_ALG_NONE = {
    id: "FA004_JWT_ALG_NONE",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW" },
    detection: { type: "REGEX", patterns: ["(?i)alg['\"]?\\s*[:=]\\s*['\"]none['\"]"] },
    presentation: { group: "Auth & Session", subgroup: "JWT", includeInSummary: true },
    explanation: {
        title: "JWT 'none' algorithm allowed",
        description: "Configuration allows JWTs with the 'none' algorithm.",
        risk: "Allows trivial token forgery by removing the signature.",
        confidenceRationale: "Explicitly allowing 'none' is a known critical vulnerability pattern.",
        recommendation: "Disallow the 'none' algorithm in JWT library configuration."
    }
};

export const FA005_JWT_VERIFICATION_DISABLED = {
    id: "FA005_JWT_VERIFICATION_DISABLED",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW" },
    detection: { type: "REGEX", patterns: ["verify:\\s*false", "ignoreExpiration:\\s*true"] },
    presentation: { group: "Auth & Session", subgroup: "JWT", includeInSummary: true },
    explanation: { title: "JWT verification disabled", description: "JWT signature or expiration check explicitly disabled.", risk: "Allows token manipulation and reuse.", recommendation: "Enable all JWT security checks." }
};

export const FA006_SAMESITE_NONE_WITHOUT_SECURE = {
    id: "FA006_SAMESITE_NONE_WITHOUT_SECURE",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    detection: { type: "COMPOSITE", composite: { allOf: ["COOKIE_SAMESITE_NONE_PRESENT", "COOKIE_SECURE_NOT_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 15 } },
    presentation: { group: "Auth & Session", subgroup: "Cookies", includeInSummary: true },
    explanation: { title: "SameSite=None used without Secure", description: "Session cookie uses SameSite=None but lacks the Secure flag.", risk: "Browsers reject these cookies, breaking sessions and potentially exposing them.", recommendation: "Set Secure: true when using SameSite: None." }
};

export const FA007_OAUTH_STATE_MISSING = {
    id: "FA007_OAUTH_STATE_MISSING",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    detection: { type: "COMPOSITE", composite: { allOf: ["OAUTH_AUTHORIZE_FLOW", "OAUTH_STATE_NOT_PRESENT"], withinSameHunk: true, withinLines: 60 } },
    presentation: { group: "Auth & Session", subgroup: "OAuth", includeInSummary: true },
    explanation: { title: "OAuth state parameter missing", description: "OAuth flow lacks a state parameter for CSRF protection.", risk: "Enables OAuth CSRF and account linking attacks.", recommendation: "Implement cryptographically random state parameters." }
};

export const FA008_SENSITIVE_ROUTE_PUBLIC = {
    id: "FA008_SENSITIVE_ROUTE_PUBLIC",
    tier: "TIER_1", kind: "FAIL", category: "Auth & Session", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    detection: { type: "COMPOSITE", composite: { allOf: ["ROUTE_DEFINITION_PRESENT", "SENSITIVE_ROUTE_KEYWORDS", "AUTH_MIDDLEWARE_NOT_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 40 } },
    presentation: { group: "Auth & Session", subgroup: "Routes", includeInSummary: true },
    explanation: { title: "Sensitive route may be public", description: "A high-risk route was added without obvious auth guards.", risk: "Privilege escalation and unauthorized data access.", recommendation: "Protect sensitive routes with authentication and authorization middleware." }
};

// IDOR001: Insecure Direct Object Reference (Insecure DB lookup by ID)
export const IDOR001_INSECURE_OBJECT_REFERENCE = {
    id: "IDOR001_INSECURE_OBJECT_REFERENCE",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Auth & Session",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["IDOR_PARAMETER_IN_URL", "IDOR_DB_LOOKUP_BY_ID", "IDOR_OWNERSHIP_CHECK_NOT_PRESENT"],
            withinSameHunk: true,
            withinLines: 30
        }
    },
    explanation: {
        title: "Insecure Direct Object Reference (IDOR)",
        description: "A database lookup is performed using an ID directly from a request parameter without an obvious ownership or authorization check.",
        risk: "IDOR (A01) allows attackers to access, modify, or delete data belonging to other users by simply changing the ID parameter in the request.",
        confidenceRationale: "Synchronous lookup of a sensitive object by ID from user input without an associated session/owner check is a high-risk IDOR pattern.",
        recommendation: "Always verify that the authenticated user has permission to access the requested resource. For example: `db.User.findOne({ _id: req.params.id, owner: req.user.id })`."
    }
};

export const FAIL_AUTH_RULES = [
    FA001_DEBUG_AUTH_BYPASS,
    FA002_WEAK_PASSWORD_HASHING,
    FA003_MFA_DISABLED_FLAG,
    FA004_JWT_ALG_NONE,
    FA005_JWT_VERIFICATION_DISABLED,
    FA006_SAMESITE_NONE_WITHOUT_SECURE,
    FA007_OAUTH_STATE_MISSING,
    FA008_SENSITIVE_ROUTE_PUBLIC,
    IDOR001_INSECURE_OBJECT_REFERENCE
];
