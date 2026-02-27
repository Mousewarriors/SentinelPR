/**
 * XSS FAIL rules
 *
 * Philosophy:
 * - Server-side reflection to res.send/write directly is deterministic RCE-adjacent.
 * - Client-side innerHTML / dangerouslySetInnerHTML with req.* data is slam-dunk.
 * - Only fire when sink + req.* source are on the SAME LINE — zero ambiguity.
 */

// XSS001: Direct request input in HTML sink (server-side or client-side)
export const XSS001_DIRECT_HTML_SINK = {
    id: "XSS001_DIRECT_HTML_SINK",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // JS/Node: res.send/write/end with req.* directly
            "(?i)\\bres\\s*\\.\\s*(send|write|end)\\s*\\(.*req\\s*\\.\\s*(query|params|body)\\.",
            // Client-side JS: innerHTML or document.write with req.*
            "(?i)\\.innerHTML\\s*=.*req\\s*\\.\\s*(query|params|body)\\.",
            "(?i)\\bdocument\\.write\\s*\\(.*req\\s*\\.\\s*(query|params|body)\\.",
            // React: dangerouslySetInnerHTML with req.*
            "(?i)dangerouslySetInnerHTML\\s*=\\s*\\{\\{?\\s*__html\\s*:.*req\\s*\\.\\s*(query|params|body)\\.",
            // Express template injection: res.render with req.* in data object
            "(?i)\\bres\\.render\\s*\\([^,]+,\\s*\\{[^}]*req\\s*\\.\\s*(query|params|body)",
            // Java Servlet: response.getWriter().print/write with request.getParameter
            "(?i)response\\.getWriter\\s*\\(\\s*\\)\\s*\\.(print|write)\\s*\\([^)]*request\\.getParameter\\(",
            "(?i)out\\.print(ln)?\\s*\\([^)]*request\\.getParameter\\(",
            // Go: fmt.Fprintf(w, ...) with r.FormValue or r.URL.Query
            "(?i)fmt\\.Fprint(f|ln)?\\s*\\(w[^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            "(?i)fmt\\.Fprint(f|ln)?\\s*\\(w[^,]+,[^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            // C#: Response.Write with Request.QueryString
            "(?i)Response\\.Write\\s*\\([^)]*Request\\.(QueryString|Form)\\[",
            "(?i)HttpContext\\.Current\\.Response\\.Write\\s*\\([^)]*Request\\[",
            // PHP: echo/print directly with superglobals (no HTML entity encoding)
            "(?i)\\b(echo|print)\\b.*\\$_(GET|POST|REQUEST|COOKIE)",
            "(?i)<\\?=\\s*\\$_(GET|POST|REQUEST|COOKIE)",
            // Ruby/Rails: render with params (no h/html_escape)
            "(?i)render\\s+(plain|html|text|inline):\\s*params\\[:",
            "(?i)render\\s+(plain|html|text|inline):\\s*[\"'][^\"']*#\\{\\s*params\\[:"
        ],
        negativePatterns: [
            // Exclude if a sanitizer is on the same line (any language)
            "(?i)(sanitize|escape|encode|DOMPurify|\\.xss\\(|validator|strip|htmlspecialchars|html_escape|h\\(|CGI\\.escapeHTML|Encoder\\.forHtml|AntiXss|json_encode)"
        ]
    },
    explanation: {
        title: "Unsanitized user input written to HTML output",
        description: "User-supplied input is passed directly into an HTML rendering or response sink without sanitization across JS, Java, Go, C#, PHP, or Ruby.",
        risk: "XSS (Cross-Site Scripting): attackers inject scripts that steal cookies/tokens, redirect users, or perform actions on their behalf. Reflected XSS in APIs serving HTML is immediately exploitable.",
        confidenceRationale: "Sink and source on the same line with no sanitization function detected — high-confidence across all supported languages.",
        recommendation: "Always encode output to HTML context. Use: DOMPurify/xss (JS), response.encodeHTML/OWASP Java Encoder (Java), html.EscapeString (Go), AntiXss.HtmlEncode (C#), htmlspecialchars (PHP), h() or ERB auto-escape (Ruby)."
    }
};

// XSS002: document.cookie written with request data (DOM-based)
export const XSS002_COOKIE_SINK_FROM_REQUEST = {
    id: "XSS002_COOKIE_SINK_FROM_REQUEST",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "MEDIUM",
    appliesTo: {
        fileGlobs: ["**/*.{js,ts,jsx,tsx}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // DOM cookie set from user input: location.hash, location.search, URLSearchParams
            "(?i)document\\.cookie\\s*=.*(?:location\\.(hash|search)|URLSearchParams|window\\.location)",
            "(?i)document\\.cookie\\s*=.*req\\.(query|params|body)"
        ]
    },
    explanation: {
        title: "Cookie written from URL/request data",
        description: "A cookie value is being set using URL parameters or request-derived data.",
        risk: "Attackers can manipulate URL parameters to set arbitrary cookie values, enabling session fixation, authentication bypass, or data injection.",
        confidenceRationale: "Cookie mutation with URL-derived input on the same line is an unambiguous pattern.",
        recommendation: "Never set cookie values from URL parameters. Generate cookie values server-side from trusted sources only."
    }
};

export const FAIL_XSS_RULES = [
    XSS001_DIRECT_HTML_SINK,
    XSS002_COOKIE_SINK_FROM_REQUEST
];
