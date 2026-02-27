/**
 * CORS / CSRF / Session WARN rules
 *
 * Philosophy:
 * - Web security config issues are frequent SaaS root causes.
 * - These are WARN (context matters), but many patterns are high-agreement.
 */

export const W1001_CORS_WILDCARD = {
    id: "W1001_CORS_WILDCARD",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,yml,yaml,json}", "**/pages/api/**", "**/app/api/**", "**/routes/**", "**/controllers/**"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["cors", "Access-Control-Allow-Origin", "origin"], withinChars: 220 } },
    detection: { type: "REGEX", patterns: ["Access-Control-Allow-Origin\\s*:\\s*\\*", "(?i)origin\\s*[:=]\\s*['\"]\\*['\"]", "(?i)allow_origin\\s*[:=]\\s*\\*"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "CORS", shortLabel: "CORS *", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "CORS allows any origin (*)", description: "CORS configuration appears to allow any origin via wildcard.", risk: "If sensitive endpoints are accessible cross-origin (especially with credentials or tokens), this can enable data theft and account compromise.", confidenceRationale: "Wildcard origins are explicit and widely recognized as risky for authenticated endpoints.", recommendation: "Use a strict allowlist of trusted origins. Avoid wildcard CORS for authenticated or sensitive endpoints." }
};


export const W1003_CORS_REFLECT_ORIGIN = {
    id: "W1003_CORS_REFLECT_ORIGIN",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**", "**/routes/**", "**/controllers/**"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["Origin", "Access-Control-Allow-Origin", "setHeader", "cors"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)Access-Control-Allow-Origin[^\\n]{0,120}(req\\.headers\\.origin|request\\.headers\\['origin'\\]|origin\\s*=\\s*req\\.)", "(?i)setHeader\\([^\\)]*Access-Control-Allow-Origin[^\\)]*(req\\.headers\\.origin|origin)"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "CORS", shortLabel: "Reflect origin", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "CORS may reflect request Origin", description: "CORS implementation appears to mirror the incoming Origin header into Access-Control-Allow-Origin.", risk: "If not paired with a strict allowlist, origin reflection effectively allows any site to read responses, enabling cross-origin data theft.", confidenceRationale: "Heuristic: some implementations reflect only after allowlist checks elsewhere.", recommendation: "Validate Origin against an allowlist before reflecting. Avoid reflection-by-default behavior." }
};

export const W1004_CORS_ALLOW_HEADERS_PERMISSIVE = {
    id: "W1004_CORS_ALLOW_HEADERS_PERMISSIVE",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["Access-Control-Allow-Headers", "allowedHeaders", "cors"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["Access-Control-Allow-Headers\\s*:\\s*\\*", "(?i)allowedHeaders\\s*[:=]\\s*['\"]\\*['\"]"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "CORS", shortLabel: "Allow-Headers *", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "CORS allowed headers may be overly permissive", description: "CORS configuration appears to allow any request headers.", risk: "Overly permissive headers can enable sending sensitive custom headers cross-origin and weaken intended access controls.", confidenceRationale: "Allow-Headers * is explicit; impact depends on origin and credential settings.", recommendation: "Allowlist only the headers you need and ensure Origin allowlists are enforced for sensitive endpoints." }
};


export const W1006_CSRF_MISSING_ON_STATE_CHANGE = {
    id: "W1006_CSRF_MISSING_ON_STATE_CHANGE",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**", "**/routes/**", "**/controllers/**", "**/handlers/**"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["POST", "PUT", "PATCH", "DELETE", "router.", "app."], withinChars: 240 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["STATE_CHANGING_ROUTE_PRESENT", "NO_CSRF_KEYWORDS_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 140 } },
    presentation: { group: "CORS / CSRF / Session", subgroup: "CSRF", shortLabel: "CSRF missing", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "State-changing route without obvious CSRF protection", description: "A state-changing endpoint was added/modified without obvious CSRF protection nearby.", risk: "If the app uses cookie-based auth, CSRF can allow attackers to trigger actions from other sites.", confidenceRationale: "Heuristic: CSRF protection may be applied globally via middleware not shown in the diff.", recommendation: "Confirm CSRF protections are applied globally or apply CSRF middleware for state-changing routes in cookie-auth contexts." }
};




export const W1010_SESSION_COOKIE_NAME_DEFAULT = {
    id: "W1010_SESSION_COOKIE_NAME_DEFAULT",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml,properties}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["session", "cookie", "name"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)connect\\.sid", "(?i)sessionid\\b", "(?i)PHPSESSID", "(?i)JSESSIONID"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Sessions", shortLabel: "Default name", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Default session cookie name referenced", description: "Code/config references common default session cookie names.", risk: "Default names are not inherently insecure, but can make targeting easier and may indicate default session config is used without hardening.", confidenceRationale: "Heuristic: cookie names alone are not vulnerabilities.", recommendation: "Ensure session cookies are hardened (Secure, HttpOnly, SameSite) and session stores are configured safely." }
};

export const W1011_SESSION_STORE_IN_MEMORY = {
    id: "W1011_SESSION_STORE_IN_MEMORY",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["session", "store", "memory"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)MemoryStore", "(?i)InMemoryStore", "(?i)memory\\s*store"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Sessions", shortLabel: "Memory store", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Session store may be in-memory", description: "Session configuration appears to use an in-memory store.", risk: "In-memory session stores can lead to session loss on restarts and may not scale; misconfigurations can also increase exposure if memory is dumped.", confidenceRationale: "The store type is detectable; security impact depends on environment and persistence requirements.", recommendation: "Use a hardened external session store (e.g., Redis) with TLS, auth, and appropriate TTLs for production." }
};

export const W1012_SESSION_TTL_VERY_LONG = {
    id: "W1012_SESSION_TTL_VERY_LONG",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml,properties,json}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["maxAge", "ttl", "expires", "session"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)maxAge\\s*[:=]\\s*(\\d{8,}|\\d+\\s*\\*\\s*\\d+\\s*\\*\\s*\\d+\\s*\\*\\s*\\d+)", "(?i)ttl\\s*[:=]\\s*\\d{7,}"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Sessions", shortLabel: "Long TTL", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Session TTL may be very long", description: "Session cookie TTL/expiration appears configured to a very long duration.", risk: "Long-lived sessions increase window for stolen session replay and reduce effectiveness of rotation and revocation.", confidenceRationale: "Heuristic: numeric thresholds vary and parsing in diffs is imperfect.", recommendation: "Use shorter TTLs for session cookies and implement refresh/rotation and revocation for long-lived access." }
};

export const W1013_JWT_IN_LOCALSTORAGE = {
    id: "W1013_JWT_IN_LOCALSTORAGE",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["localStorage", "sessionStorage", "token", "jwt"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["localStorage\\.(setItem|getItem)\\([^\\)]*(token|jwt)", "sessionStorage\\.(setItem|getItem)\\([^\\)]*(token|jwt)"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Tokens", shortLabel: "Token storage", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Tokens/JWT stored in web storage", description: "Code stores or retrieves tokens/JWTs from localStorage/sessionStorage.", risk: "Web storage is accessible to JavaScript; XSS can exfiltrate tokens leading to account takeover.", confidenceRationale: "Patterns are direct; not all tokens are equally sensitive, but common practice is to avoid storing auth tokens in localStorage.", recommendation: "Prefer HttpOnly Secure cookies for session tokens or use in-memory tokens with robust XSS mitigations and rotation." }
};

export const W1014_AUTH_MIDDLEWARE_BYPASS = {
    id: "W1014_AUTH_MIDDLEWARE_BYPASS",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["auth", "authenticate", "middleware", "guard", "skip"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)skip(Auth|Authentication|Authorize)", "(?i)noAuth\\b", "(?i)disableAuth\\b", "(?i)publicRoute\\b"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Auth", shortLabel: "Auth bypass", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Auth middleware bypass pattern introduced", description: "Code introduces patterns suggesting authentication may be skipped for some routes.", risk: "Accidental auth bypass can expose sensitive endpoints and lead to unauthorized access.", confidenceRationale: "Heuristic: some apps intentionally allow public endpoints; still warrants explicit review.", recommendation: "Ensure bypasses are scoped to intended public routes only and are covered by tests and explicit route allowlists." }
};

export const W1015_OPEN_REDIRECT_NEXT_URL = {
    id: "W1015_OPEN_REDIRECT_NEXT_URL",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["redirect", "next", "returnTo", "continue", "url"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)redirect\\([^\\)]*(req\\.(query|params)|params\\[|request\\.)", "(?i)(next|returnTo|continue)\\s*[:=]\\s*(req\\.(query|params)|request\\.)"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Redirects", shortLabel: "Open redirect", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Potential open redirect via user-controlled URL parameter", description: "Redirect destination appears derived from user input (e.g., next/returnTo parameter).", risk: "Open redirects enable phishing and can be chained with auth flows to steal tokens or perform login CSRF.", confidenceRationale: "Heuristic: safe implementations validate against same-origin or allowlists.", recommendation: "Allowlist redirect destinations (same-origin paths only) and reject absolute URLs or external hosts." }
};

export const W1016_SET_COOKIE_WITHOUT_DOMAIN_PATH = {
    id: "W1016_SET_COOKIE_WITHOUT_DOMAIN_PATH",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["Set-Cookie", "cookie", "domain", "path"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)set-cookie", "(?i)res\\.cookie\\("] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Cookies", shortLabel: "Cookie scope", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Cookie scope settings should be reviewed", description: "Cookie setting logic changed; ensure Domain/Path scoping is appropriate.", risk: "Overly broad cookie scope can lead to unintended exposure across subdomains or paths, increasing risk of theft or fixation.", confidenceRationale: "Heuristic: cookie APIs vary; the important part is reviewing final cookie attributes.", recommendation: "Set Path and Domain intentionally. Avoid broad Domain unless necessary; use __Host- / __Secure- prefixes where possible." }
};

export const W1017_ALLOW_IFRAME_XFO_DISABLED = {
    id: "W1017_ALLOW_IFRAME_XFO_DISABLED",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["X-Frame-Options", "frame-ancestors", "clickjacking"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)X-Frame-Options\\s*:\\s*(ALLOWALL|ALLOW-FROM|\\s*$)", "(?i)frame-ancestors\\s+'\\*'"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Browser protections", shortLabel: "Iframes", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Clickjacking protections may be weakened", description: "X-Frame-Options / frame-ancestors policy appears permissive.", risk: "Without clickjacking protections, attackers can frame sensitive pages and trick users into unintended clicks.", confidenceRationale: "Header/policy strings are explicit; exact impact depends on app pages and auth flows.", recommendation: "Use frame-ancestors allowlists (CSP) and/or X-Frame-Options DENY/SAMEORIGIN where appropriate." }
};

export const W1018_CSP_DISABLED_OR_REPORT_ONLY = {
    id: "W1018_CSP_DISABLED_OR_REPORT_ONLY",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["Content-Security-Policy", "CSP", "report-only"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)Content-Security-Policy-Report-Only", "(?i)Content-Security-Policy\\s*:\\s*$"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Browser protections", shortLabel: "CSP", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "CSP may be report-only or missing", description: "CSP appears set to report-only or is not clearly enforced in the changed configuration.", risk: "A strong CSP reduces XSS impact; report-only does not block attacks.", confidenceRationale: "Heuristic: CSP could be set elsewhere; enforcement is deployment-specific.", recommendation: "Enforce CSP for sensitive apps and avoid unsafe directives like 'unsafe-inline' unless necessary and reviewed." }
};

export const W1019_RATE_LIMIT_DISABLED = {
    id: "W1019_RATE_LIMIT_DISABLED",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml,env}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["rate", "limit", "throttle", "ddos"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)rate[_-]?limit\\s*[:=]\\s*false", "(?i)disable\\s*rate\\s*limit", "(?i)throttle\\s*:\\s*false"] },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Abuse controls", shortLabel: "Rate limit", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Rate limiting may be disabled", description: "Configuration suggests rate limiting or throttling is disabled.", risk: "Disabling rate limits increases brute-force, credential stuffing, and DoS risk.", confidenceRationale: "Heuristic: rate limiting may be enforced at a gateway/WAF instead.", recommendation: "Ensure rate limiting exists at some layer for login and sensitive endpoints and is monitored/alerted." }
};

export const W1020_ADMIN_ROUTE_NO_AUTH_GUARD = {
    id: "W1020_ADMIN_ROUTE_NO_AUTH_GUARD",
    tier: "TIER_1", kind: "WARN", category: "CORS / CSRF / Session", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["admin", "/admin", "dashboard", "manage", "auth", "guard"], withinChars: 260 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["ADMIN_ROUTE_PATTERN_PRESENT", "NO_AUTH_GUARD_KEYWORDS_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 120 } },
    presentation: { group: "CORS / CSRF / Session", subgroup: "Auth", shortLabel: "Admin guard", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Admin route added without obvious auth guard", description: "An admin-like route or handler was added without obvious authentication/authorization enforcement nearby.", risk: "Admin endpoints without guards can expose privileged actions and sensitive data.", confidenceRationale: "Heuristic: auth may be applied globally via router/group middleware not shown in diff.", recommendation: "Confirm admin routes are protected by explicit auth + authorization middleware and covered by tests." }
};

export const WARN_WEB_RULES = [
    W1001_CORS_WILDCARD, W1003_CORS_REFLECT_ORIGIN, W1004_CORS_ALLOW_HEADERS_PERMISSIVE, W1006_CSRF_MISSING_ON_STATE_CHANGE, W1010_SESSION_COOKIE_NAME_DEFAULT, W1011_SESSION_STORE_IN_MEMORY, W1012_SESSION_TTL_VERY_LONG, W1013_JWT_IN_LOCALSTORAGE, W1014_AUTH_MIDDLEWARE_BYPASS, W1015_OPEN_REDIRECT_NEXT_URL, W1016_SET_COOKIE_WITHOUT_DOMAIN_PATH, W1017_ALLOW_IFRAME_XFO_DISABLED, W1018_CSP_DISABLED_OR_REPORT_ONLY, W1019_RATE_LIMIT_DISABLED, W1020_ADMIN_ROUTE_NO_AUTH_GUARD
];
