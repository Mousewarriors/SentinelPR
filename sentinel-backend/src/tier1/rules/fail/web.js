/**
 * CORS / CSRF / Session FAIL rules
 *
 * These rules are high-confidence escalations of WARN rules.
 */

export const SEC001_CORS_WILDCARD_WITH_CREDENTIALS = {
    id: "SEC001_CORS_WILDCARD_WITH_CREDENTIALS",
    tier: "TIER_1", kind: "FAIL", category: "CORS / CSRF / Session", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["CORS_WILDCARD_PRESENT", "CORS_CREDENTIALS_TRUE_PRESENT"],
            withinSameHunk: true
        }
    },
    explanation: {
        title: "CORS wildcard origin with credentials enabled",
        description: "CORS allows any origin (*) while also allowing credentials.",
        risk: "Allows any malicious site to perform authenticated requests and read responses from this server, leading to full account takeover.",
        confidenceRationale: "This is a mathematically certain vulnerability in standard CORS implementations.",
        recommendation: "Never use wildcard origins with credentials. Use a strict allowlist of origins."
    }
};

export const SEC002_CSRF_EXPLICITLY_DISABLED = {
    id: "SEC002_CSRF_EXPLICITLY_DISABLED",
    tier: "TIER_1", kind: "FAIL", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,yml,yaml,env,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "DISABLE_CSRF=true",
            "CSRF_DISABLED=true",
            "ENABLE_CSRF=false",
            "csrf:\\s*false",
            "disableCsrf:\\s*true"
        ]
    },
    explanation: {
        title: "CSRF protection explicitly disabled",
        description: "Configuration explicitly disables CSRF protection.",
        risk: "Disabling CSRF allows attackers to perform state-changing actions on behalf of a victim user.",
        confidenceRationale: "The detection matches explicit disabling flags.",
        recommendation: "Always enable CSRF for cookie-based applications. Use SameSite: Strict/Lax and anti-CSRF tokens."
    }
};

export const SEC003_COOKIE_HTTPONLY_FALSE = {
    id: "SEC003_COOKIE_HTTPONLY_FALSE",
    tier: "TIER_1", kind: "FAIL", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: { type: "REGEX", patterns: ["httpOnly:\\s*false"] },
    explanation: {
        title: "Cookie httpOnly explicitly disabled",
        description: "Cookie configuration explicitly sets httpOnly to false.",
        risk: "Allows client-side JavaScript to read session cookies, making the application vulnerable to session theft via XSS.",
        confidenceRationale: "Triggers only on explicit 'false' configuration.",
        recommendation: "Set httpOnly: true for all session and authentication cookies."
    }
};

export const SEC004_COOKIE_SECURE_FALSE = {
    id: "SEC004_COOKIE_SECURE_FALSE",
    tier: "TIER_1", kind: "FAIL", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: { type: "REGEX", patterns: ["secure:\\s*false"] },
    explanation: {
        title: "Cookie secure flag explicitly disabled",
        description: "Cookie configuration explicitly sets secure to false.",
        risk: "Allows cookies to be sent over unencrypted HTTP connections, exposing them to network interception.",
        confidenceRationale: "Triggers only on explicit 'false' configuration.",
        recommendation: "Set secure: true for all production cookies and enforce HTTPS."
    }
};

export const SEC005_SAMESITE_NONE_WITHOUT_SECURE = {
    id: "SEC005_SAMESITE_NONE_WITHOUT_SECURE",
    tier: "TIER_1", kind: "FAIL", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["SAMESITE_NONE_PRESENT", "SECURE_FALSE_OR_MISSING_NEARBY"],
            withinSameHunk: true
        }
    },
    explanation: {
        title: "SameSite: None used without Secure: true",
        description: "Cookie sets 'sameSite: none' but does not enable the 'secure' flag.",
        risk: "Modern browsers reject 'SameSite=None' cookies unless they are also marked as 'Secure'. This can cause session issues and bypass intended protections.",
        confidenceRationale: "Triggers on explicit configuration mismatch.",
        recommendation: "Always set secure: true when using sameSite: 'none'."
    }
};

export const SEC006_CORS_WILDCARD = {
    id: "SEC006_CORS_WILDCARD",
    tier: "TIER_1", kind: "FAIL", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    detection: { type: "REGEX", patterns: ["Access-Control-Allow-Origin\\s*:\\s*\\*", "(?i)origin\\s*[:=]\\s*['\"]\\*['\"]"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "CORS", includeInSummary: true },
    explanation: { title: "CORS allows any origin (*)", description: "Permissive CORS configuration detected.", risk: "Sensitive data exposure to third-party sites.", recommendation: "Specify trusted origins." }
};

export const SEC007_JWT_IN_LOCALSTORAGE = {
    id: "SEC007_JWT_IN_LOCALSTORAGE",
    tier: "TIER_1", kind: "FAIL", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    detection: { type: "REGEX", patterns: ["localStorage\\.(setItem|getItem)\\([^\\)]*(token|jwt)"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Tokens", includeInSummary: true },
    explanation: { title: "Auth token stored in web storage", description: "Storage of sensitive tokens in localStorage detected.", risk: "Exposed to XSS exfiltration.", recommendation: "Use HttpOnly Secure cookies." }
};

// SEC008: Server-Side Request Forgery (SSRF) via direct request input
export const SEC008_SSRF_VULNERABILITY = {
    id: "SEC008_SSRF_VULNERABILITY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "CORS / CSRF / Session",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["HTTP_REQUEST_SINK", "HAS_NEAR_SOURCE"], withinSameHunk: true }
    },
    explanation: {
        title: "Potential SSRF via direct user input in HTTP request",
        description: "A user-supplied value is passed directly to a network request sink without validation.",
        risk: "Enables Server-Side Request Forgery (SSRF), allowing attackers to reach internal infrastructure, cloud metadata services (169.254.169.254), or internal APIs on behalf of the server.",
        confidenceRationale: "A user-input source and an HTTP client sink on the same line is a near-certain SSRF indicator across all languages.",
        recommendation: "Never allow users to specify arbitrary URLs. Enforce an allowlist of permitted domains/schemes and validate all URLs server-side before making requests."
    }
};

// OPEN001: Direct res.redirect / header Location with unvalidated request input
export const OPEN001_OPEN_REDIRECT = {
    id: "OPEN001_OPEN_REDIRECT",
    tier: "TIER_1",
    kind: "FAIL",
    category: "CORS / CSRF / Session",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["REDIRECT_SINK", "HAS_NEAR_SOURCE"], withinSameHunk: true }
    },
    explanation: {
        title: "Unvalidated open redirect",
        description: "A redirect target is directly derived from user input in JavaScript, Ruby, PHP, Java, Go, or C# with no validation detected.",
        risk: "Open redirects enable phishing via trusted-domain abuse, OAuth token theft via redirect_uri hijacking, and SSRF chain attacks.",
        confidenceRationale: "Redirect sink + user-input source on the same line with no allowlist or path-check detected.",
        recommendation: "Only redirect to relative paths or a strict allowlist of known domains. Reject absolute URLs from user input or validate hostname against an allowlist."
    }
};

// MASS001: Mass Assignment (Insecure Object Hydration)
export const MASS001_MASS_ASSIGNMENT = {
    id: "MASS001_MASS_ASSIGNMENT",
    tier: "TIER_1",
    kind: "FAIL",
    category: "CORS / CSRF / Session",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,rb,java,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Node/JS: Object.assign or _.merge with req.body directly into a model-like object
            "(?i)Object\\.assign\\s*\\([^,]+,\\s*req\\.body\\)",
            "(?i)_\\.(merge|extend|assign)\\s*\\([^,]+,\\s*req\\.body\\)",
            // Ruby/Rails: No permit()/slice() on params before assignment
            "(?i)\\b(update|create|new)\\s*\\(\\s*params\\[",
            "(?i)\\b(update_attributes|assign_attributes)\\s*\\(\\s*params\\["
        ],
        negativePatterns: [
            // Exclude if permit() or slice() is used (Rails)
            "\\.permit\\s*\\(",
            "\\.slice\\s*\\(",
            // Exclude if property-specific assignment is detected (Node)
            "req\\.body\\.[a-zA-Z0-9]+"
        ]
    },
    explanation: {
        title: "Mass Assignment (Insecure Object Hydration)",
        description: "Request data (req.body or params) is assigned directly to an object or database model without filtering which properties are allowed.",
        risk: "Attackers can supply unexpected properties (e.g., {'role': 'admin', 'isAdmin': true}) to escalate privileges or bypass business logic during object creation or updates.",
        confidenceRationale: "Directly assigning request objects to models without a permit/allowlist filter is a classic high-risk pattern.",
        recommendation: "Use allowlisting to restrict which properties can be updated from user input. In Rails, use Strong Parameters (`params.require(...).permit(...)`). In Node, use an explicit mapping or a library like `lodash.pick`."
    }
};

// CRLF001: CRLF Injection / Response Splitting
export const CRLF001_CRLF_INJECTION = {
    id: "CRLF001_CRLF_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "CORS / CSRF / Session",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // req input in setHeader/append
            "(?i)\\.(setHeader|append|header|AddHeader)\\s*\\([^,]+,[^)]*req\\.(query|params|body)",
            "(?i)\\.(setHeader|append|header|AddHeader)\\s*\\([^,]+,[^)]*request\\.(getParameter|args|form)",
            // Specific CRLF character sequences
            "(\\\\r\\\\n|\\r\\n).{0,50}req\\.",
            "(\\\\r\\\\n|\\r\\n).{0,50}request\\."
        ]
    },
    explanation: {
        title: "CRLF Injection / HTTP Response Splitting",
        description: "User input is included in an HTTP response header without removing or escaping newline characters (CR/LF).",
        risk: "Allows attackers to inject arbitrary headers, split the HTTP response, and perform cache poisoning, XSS, or unauthorized redirects.",
        confidenceRationale: "Setting headers directly from uncleaned request input is a high-confidence indicator of CRLF risk.",
        recommendation: "Sanitize all user input used in HTTP headers by removing or replacing carriage return (\r) and line feed (\n) characters."
    }
};

// HOST001: HTTP Host Header Injection
export const HOST001_HOST_HEADER_INJECTION = {
    id: "HOST001_HOST_HEADER_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "CORS / CSRF / Session",
    severity: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Use of Host header in URL building or sensitive logic
            "(?i)req\\.get\\s*\\(['\"]Host['\"]\\)",
            "(?i)req\\.headers\\[['\"]host['\"]\\]",
            "(?i)request\\.headers\\.(get|)[^a-zA-Z0-9]* host",
            "(?i)\\$_(SERVER|REQUEST)\\[['\"]HTTP_HOST['\"]\\]"
        ]
    },
    explanation: {
        title: "HTTP Host Header Injection",
        description: "The application uses the 'Host' header from the HTTP request to build URLs or in sensitive logic (e.g., password reset links).",
        risk: "Attackers can manipulate the Host header to point to a malicious domain, leading to password reset poisoning, cache poisoning, or unauthorized redirects.",
        confidenceRationale: "Directly relying on the Host header for security-sensitive URL construction is a documented misconfiguration.",
        recommendation: "Use a hardcoded base URL for the application in production or validate the Host header against an allowlist of permitted domains."
    }
};

export const FAIL_WEB_RULES = [
    SEC001_CORS_WILDCARD_WITH_CREDENTIALS,
    SEC002_CSRF_EXPLICITLY_DISABLED,
    SEC003_COOKIE_HTTPONLY_FALSE,
    SEC004_COOKIE_SECURE_FALSE,
    SEC005_SAMESITE_NONE_WITHOUT_SECURE,
    SEC006_CORS_WILDCARD,
    SEC007_JWT_IN_LOCALSTORAGE,
    SEC008_SSRF_VULNERABILITY,
    OPEN001_OPEN_REDIRECT,
    MASS001_MASS_ASSIGNMENT,
    CRLF001_CRLF_INJECTION,
    HOST001_HOST_HEADER_INJECTION
];
