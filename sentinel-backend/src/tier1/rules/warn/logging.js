/**
 * Logging & Observability WARN rules
 *
 * Philosophy:
 * - Logs are a primary data-exfiltration path in SaaS.
 * - These rules focus on high-agreement risky behaviors:
 *   logging secrets, auth headers, cookies, whole request bodies/headers,
 *   enabling debug in prod configs, leaking stack traces, and exposing metrics/traces publicly.
 */

export const L801_LOG_SECRETS_TOKENS = {
    id: "L801_LOG_SECRETS_TOKENS",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["log", "logger", "console", "print"], withinChars: 140 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|client[_-]?secret)\\b[^\\n]{0,60}\\b(log|logger|console\\.log|print)\\b", "(?i)\\b(log|logger|console\\.log|print)\\b[^\\n]{0,80}\\b(token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|client[_-]?secret)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Secrets in logs", shortLabel: "Secrets logged", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Potential secrets/tokens logged", description: "Logging statements appear to include token/secret-like fields.", risk: "Logs are commonly accessible to many systems and people; logging secrets enables credential theft and lateral movement.", confidenceRationale: "The rule uses keyword proximity, but exact sensitivity depends on the value being logged and redaction configuration.", recommendation: "Never log secrets or tokens. Use structured logging with redaction/allowlists and log only stable identifiers." }
};

export const L802_LOG_AUTHORIZATION_HEADER = {
    id: "L802_LOG_AUTHORIZATION_HEADER",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["log", "logger", "console", "print"], withinChars: 160 } },
    detection: { type: "REGEX", patterns: ["(?i)authorization\\b[^\\n]{0,80}\\b(log|logger|console\\.log|print)\\b", "(?i)\\b(log|logger|console\\.log|print)\\b[^\\n]{0,80}\\bauthorization\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Secrets in logs", shortLabel: "Auth header", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Authorization header may be logged", description: "Logging includes the Authorization header or equivalent auth header value.", risk: "Authorization headers often contain bearer tokens or credentials; logging them can lead to account takeover.", confidenceRationale: "Authorization header logging is highly specific and almost always unsafe.", recommendation: "Never log Authorization headers. If needed, log only the auth scheme (e.g., 'Bearer') and redact token values." }
};

export const L803_LOG_REQUEST_HEADERS_WHOLESALE = {
    id: "L803_LOG_REQUEST_HEADERS_WHOLESALE",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(log|logger|console\\.log|print)\\b[^\\n]{0,80}\\b(req\\.headers|request\\.headers|headers\\(\\)|getHeaders\\(\\))\\b", "(?i)\\b(req\\.headers|request\\.headers)\\b[^\\n]{0,80}\\b(log|logger|console\\.log|print)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Request logging", shortLabel: "Headers logged", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Request headers may be logged wholesale", description: "Code logs the entire request headers object.", risk: "Headers may contain Authorization tokens, cookies, CSRF tokens, or PII; wholesale logging increases exposure.", confidenceRationale: "Logging headers objects is detectable, but some environments have redaction middleware—so warn-level.", recommendation: "Log an allowlist of non-sensitive headers. Ensure Authorization/Cookie headers are always redacted." }
};

export const L804_LOG_REQUEST_BODY_WHOLESALE = {
    id: "L804_LOG_REQUEST_BODY_WHOLESALE",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["log", "logger", "console", "print"], withinChars: 120 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(log|logger|console\\.log|print)\\b[^\\n]{0,80}\\b(req\\.body|request\\.body|body\\(\\))\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Request logging", shortLabel: "Body logged", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Request body may be logged wholesale", description: "Code logs the entire request body.", risk: "Request bodies frequently contain passwords, tokens, personal data, and payment data; wholesale logging increases breach impact.", confidenceRationale: "Pattern is clear, but whether the body contains sensitive data depends on endpoint usage and redaction.", recommendation: "Avoid logging request bodies. Log stable identifiers and validated fields only, with redaction/allowlists." }
};

export const L805_LOG_SESSION_COOKIE = {
    id: "L805_LOG_SESSION_COOKIE",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["cookie", "session", "set-cookie"], withinChars: 180 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(cookie|set-cookie|sessionid|session_id|sid)\\b[^\\n]{0,80}\\b(log|logger|console\\.log|print)\\b", "(?i)\\b(log|logger|console\\.log|print)\\b[^\\n]{0,80}\\b(cookie|set-cookie|sessionid|session_id|sid)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Secrets in logs", shortLabel: "Cookie logged", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Session cookie value may be logged", description: "Logging statements appear to include cookie or session identifier values.", risk: "Session identifiers can be replayed to hijack sessions if exposed through logs.", confidenceRationale: "Cookie/session keywords are strong, but exact sensitivity depends on redaction/masking.", recommendation: "Never log raw cookie/session values. Redact or hash identifiers if needed for debugging." }
};

export const L806_DEBUG_LOGGING_ENABLED = {
    id: "L806_DEBUG_LOGGING_ENABLED",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{env,properties,yml,yaml,json,js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bDEBUG\\s*=\\s*(true|1)\\b", "(?i)\\blog_level\\s*[:=]\\s*(debug|trace)\\b", "(?i)\\blogging\\.level\\..*\\s*=\\s*(DEBUG|TRACE)\\b", "(?i)\\bRACK_ENV\\s*=\\s*development\\b", "(?i)\\bFLASK_ENV\\s*=\\s*development\\b", "(?i)\\bNODE_ENV\\s*=\\s*development\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Debug toggles", shortLabel: "Debug enabled", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Debug or verbose logging may be enabled", description: "Configuration enables debug mode or sets logging to DEBUG/TRACE.", risk: "Debug/trace logs can include sensitive request data, secrets, stack traces, and internal details, increasing breach impact.", confidenceRationale: "These toggles are explicit configuration changes.", recommendation: "Ensure debug/trace logging is disabled in production environments and sensitive fields are always redacted." }
};

export const L807_STACKTRACE_LOGGED_IN_PROD = {
    id: "L807_STACKTRACE_LOGGED_IN_PROD",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["stack", "trace", "exception", "error"], withinChars: 180 } },
    detection: { type: "REGEX", patterns: ["(?i)printStackTrace\\(", "(?i)traceback\\.format_exc\\(", "(?i)console\\.error\\([^\\)]*err", "(?i)logger\\.(error|fatal)\\([^\\)]*(stack|trace)"] },
    presentation: { group: "Logging & Observability", subgroup: "Stack traces", shortLabel: "Stack trace", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Stack traces may be logged with sensitive context", description: "Code logs stack traces or error objects that may contain sensitive context.", risk: "Stack traces can leak secrets in error messages, internal file paths, query strings, and PII depending on error sources.", confidenceRationale: "Logging errors is normal; risk depends on what is included and redaction configuration.", recommendation: "Log structured error codes and minimal context. Use centralized error reporting with redaction controls." }
};

export const L808_ERROR_DETAILS_RETURNED_TO_CLIENT = {
    id: "L808_ERROR_DETAILS_RETURNED_TO_CLIENT",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["res.", "response", "render", "json", "send", "status"], withinChars: 220 } },
    detection: { type: "REGEX", patterns: ["(?i)res\\.(json|send)\\([^\\)]*(error|err|exception|stack|trace)", "(?i)return\\s+.*(error|err|exception)\\.(message|stack)"] },
    presentation: { group: "Logging & Observability", subgroup: "Error handling", shortLabel: "Error leak", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Detailed errors may be returned to clients", description: "Code appears to return raw error messages or stack traces in HTTP responses.", risk: "Exposes internal details and sometimes secrets, helping attackers exploit the system.", confidenceRationale: "Heuristic: response handling differs by framework and may be dev-only.", recommendation: "Return generic error responses to clients and log detailed errors internally with redaction." }
};

export const L809_SENSITIVE_FIELDS_IN_STRUCTURED_LOGS = {
    id: "L809_SENSITIVE_FIELDS_IN_STRUCTURED_LOGS",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["logger", "log", "audit", "event", "metadata"], withinChars: 220 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(email|phone|dob|dateOfBirth|ssn|socialSecurity|passport|address|creditCard|cardNumber|cvv)\\b\\s*[:=]"] },
    presentation: { group: "Logging & Observability", subgroup: "PII", shortLabel: "PII fields", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Potential PII fields included in logs", description: "Structured logging appears to include fields commonly treated as PII.", risk: "PII in logs increases compliance burden (GDPR/CCPA) and increases breach impact if log stores are accessed.", confidenceRationale: "This is heuristic; field names may not always represent actual PII content.", recommendation: "Avoid logging PII. Use allowlists for log fields and apply redaction/tokenization for sensitive data." }
};

export const L810_TRACE_EXPORTER_INSECURE_ENDPOINT = {
    id: "L810_TRACE_EXPORTER_INSECURE_ENDPOINT",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,java,go,yml,yaml,json,properties}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["otlp", "opentelemetry", "jaeger", "zipkin", "exporter", "collector"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["\\bhttp://[^\\s'\"]+\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Tracing", shortLabel: "Trace HTTP", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Tracing exporter/collector endpoint uses HTTP", description: "Observability exporter configuration appears to use an insecure http:// endpoint.", risk: "Telemetry can include identifiers and request metadata; HTTP transport can be intercepted or modified in transit.", confidenceRationale: "http:// endpoint references are deterministic; whether sensitive data is present depends on instrumentation.", recommendation: "Use TLS (https://) for telemetry export or restrict transport to private networks with strong controls." }
};

export const L811_METRICS_ENDPOINT_PUBLIC_BIND = {
    id: "L811_METRICS_ENDPOINT_PUBLIC_BIND",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,go,java,cs,yml,yaml,properties}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["metrics", "prometheus", "actuator", "bind", "listen", "0.0.0.0"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["\\b0\\.0\\.0\\.0\\b", "\\b:\\s*(9090|9100|9464|8081|8000)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Metrics", shortLabel: "Metrics bind", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Metrics endpoint may bind publicly", description: "Metrics server/bind configuration suggests a public interface (0.0.0.0) or common metrics ports.", risk: "Public metrics endpoints can leak internal topology, versions, and operational data useful to attackers.", confidenceRationale: "Heuristic: port usage and bind addresses can be legitimate behind firewalls.", recommendation: "Bind metrics to localhost/private interfaces and protect endpoints with network policy and authentication where appropriate." }
};

export const L812_CONSOLE_LOG_IN_SERVER_CODE = {
    id: "L812_CONSOLE_LOG_IN_SERVER_CODE",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "LOW", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\bconsole\\.(log|debug|info|warn|error)\\("] },
    presentation: { group: "Logging & Observability", subgroup: "Hygiene", shortLabel: "console.*", maxFindingsPerPR: 5, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "console logging added", description: "console.* logging was added in JavaScript/TypeScript code.", risk: "console logs can unintentionally print sensitive data and often lack redaction/structure.", confidenceRationale: "Deterministic pattern; risk depends on content and environment.", recommendation: "Prefer structured logging with redaction controls. Avoid logging sensitive values and remove debug logs before production." }
};

export const L813_LOGGER_LEVEL_TRACE_OR_DEBUG = {
    id: "L813_LOGGER_LEVEL_TRACE_OR_DEBUG",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,properties,json,env}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 256, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\blog(ging)?\\.level\\b.*\\b(TRACE|DEBUG)\\b", "(?i)\\blog_level\\b\\s*[:=]\\s*(trace|debug)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Debug toggles", shortLabel: "Trace/Debug", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Logging level set to TRACE/DEBUG", description: "Configuration sets logging level to TRACE or DEBUG.", risk: "Verbose logs can include sensitive request/response data and internal details, increasing breach impact.", confidenceRationale: "Logging level values are explicit configuration changes.", recommendation: "Use INFO/WARN/ERROR in production and ensure sensitive fields are redacted at the logger sink." }
};

export const L814_DISABLE_LOG_REDACTION = {
    id: "L814_DISABLE_LOG_REDACTION",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml,json,env}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["redact", "mask", "sanitize", "scrub"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)redact\\s*[:=]\\s*false", "(?i)mask\\s*[:=]\\s*false", "(?i)sanitize\\s*[:=]\\s*false"] },
    presentation: { group: "Logging & Observability", subgroup: "Redaction", shortLabel: "Redaction off", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Log redaction/masking may be disabled", description: "Logging configuration appears to disable redaction, masking, or sanitization.", risk: "Disabling redaction increases likelihood of secrets/PII appearing in logs and being retained in log stores.", confidenceRationale: "Settings are explicit but implementations vary by library.", recommendation: "Enable redaction and use allowlists for logged fields. Ensure Authorization/cookies/tokens are always masked." }
};

export const L815_LOG_SQL_QUERIES_WITH_PARAMS = {
    id: "L815_LOG_SQL_QUERIES_WITH_PARAMS",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["sql", "query", "params", "bind", "logger", "log"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(log|logger)\\b[^\\n]{0,120}\\b(query|sql)\\b[^\\n]{0,120}\\b(params|bind|values)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Data leakage", shortLabel: "SQL params", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "SQL queries with parameters may be logged", description: "Logging appears to include SQL queries along with bound parameters.", risk: "Query parameters may include PII, secrets, or other sensitive data that should not be stored in logs.", confidenceRationale: "Heuristic: SQL logging is sometimes safe if parameters are excluded or redacted.", recommendation: "Avoid logging SQL parameters. If query logging is needed, log query templates only or redact sensitive fields." }
};

export const L816_LOG_PASSWORD_RESET_LINKS = {
    id: "L816_LOG_PASSWORD_RESET_LINKS",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["reset", "password", "token", "link", "log", "logger"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)password\\s*reset[^\\n]{0,120}\\b(log|logger|console\\.log|print)\\b", "(?i)reset[_-]?token[^\\n]{0,80}\\b(log|logger|console\\.log|print)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Secrets in logs", shortLabel: "Reset token", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Password reset tokens/links may be logged", description: "Logging appears to include password reset tokens or links.", risk: "Reset links/tokens can be replayed to take over accounts if exposed via logs.", confidenceRationale: "Reset-token keywords are strong, but code context can vary; warn-level is appropriate.", recommendation: "Never log reset tokens/links. Log only event IDs and user identifiers (redacted) for auditing." }
};

export const L817_LOG_WEBHOOK_PAYLOADS = {
    id: "L817_LOG_WEBHOOK_PAYLOADS",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["webhook", "payload", "signature", "event", "log", "logger"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)webhook[^\\n]{0,120}(payload|body)[^\\n]{0,120}\\b(log|logger|console\\.log|print)\\b", "(?i)\\b(log|logger|console\\.log|print)\\b[^\\n]{0,120}\\bwebhook\\b[^\\n]{0,120}\\b(payload|body)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Data leakage", shortLabel: "Webhook logs", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Webhook payloads may be logged", description: "Logging appears to include webhook payload bodies or full events.", risk: "Webhook payloads can contain PII, secrets, customer data, or replayable event content.", confidenceRationale: "Heuristic: sometimes logging is necessary for debugging but should be scoped and redacted.", recommendation: "Avoid logging full webhook payloads. Log event IDs and minimal metadata; redact sensitive fields." }
};

export const L818_LOG_FILE_UPLOAD_METADATA = {
    id: "L818_LOG_FILE_UPLOAD_METADATA",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["upload", "file", "filename", "content-type", "multipart", "log"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)(upload|multipart)[^\\n]{0,120}\\b(log|logger|console\\.log|print)\\b", "(?i)filename\\b[^\\n]{0,80}\\b(log|logger|console\\.log|print)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Data leakage", shortLabel: "Upload logs", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "File upload metadata may be logged", description: "Logging appears to include file upload metadata (filenames/content-type).", risk: "Filenames and metadata may contain customer identifiers or sensitive info and can aid attackers in targeting uploads.", confidenceRationale: "Heuristic: logging metadata can be safe if minimal and redacted.", recommendation: "Log only minimal, non-sensitive upload metadata and avoid logging user-provided filenames verbatim." }
};

export const L819_LOG_JWT_CLAIMS_FULL = {
    id: "L819_LOG_JWT_CLAIMS_FULL",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["jwt", "claims", "decode", "payload", "log"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)jwt\\.(decode|verify)\\([^\\)]*\\)[^\\n]{0,80}\\b(log|logger|console\\.log|print)\\b", "(?i)claims\\b[^\\n]{0,80}\\b(log|logger|console\\.log|print)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Data leakage", shortLabel: "JWT claims", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "JWT claims/payload may be logged", description: "Logging appears to include decoded JWT payload/claims.", risk: "JWT payloads can include PII, roles, scopes, and identifiers; logging them increases exposure and retention risk.", confidenceRationale: "Heuristic: decoding tokens is common; logging the result is what introduces risk.", recommendation: "Avoid logging full JWT payloads. Log minimal identifiers (e.g., user ID) and redact sensitive claims." }
};

export const L820_LOG_EXCEPTION_WITH_REQUEST_CONTEXT = {
    id: "L820_LOG_EXCEPTION_WITH_REQUEST_CONTEXT",
    tier: "TIER_1", kind: "WARN", category: "Logging & Observability", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["catch", "except", "rescue", "error", "req", "request", "logger"], withinChars: 280 } },
    detection: { type: "REGEX", patterns: ["(?i)(catch\\s*\\(|except\\s*\\:|rescue\\s*)[\\s\\S]{0,200}\\b(log|logger|console\\.error|print)\\b[\\s\\S]{0,200}\\b(req\\.|request\\.|headers|body|query|params)\\b"] },
    presentation: { group: "Logging & Observability", subgroup: "Error handling", shortLabel: "Error+req", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Exception logging may include request context", description: "Exception handling logs errors together with request context (headers/body/params).", risk: "Request context frequently contains secrets and PII; coupling it with exception logs increases exposure and retention.", confidenceRationale: "Heuristic: request context may be redacted, but in many systems it is not.", recommendation: "Log minimal error context and avoid attaching full request objects. Redact sensitive fields aggressively." }
};

export const WARN_LOGGING_RULES = [
    L801_LOG_SECRETS_TOKENS, L802_LOG_AUTHORIZATION_HEADER, L803_LOG_REQUEST_HEADERS_WHOLESALE, L804_LOG_REQUEST_BODY_WHOLESALE, L805_LOG_SESSION_COOKIE, L806_DEBUG_LOGGING_ENABLED, L807_STACKTRACE_LOGGED_IN_PROD, L808_ERROR_DETAILS_RETURNED_TO_CLIENT, L809_SENSITIVE_FIELDS_IN_STRUCTURED_LOGS, L810_TRACE_EXPORTER_INSECURE_ENDPOINT, L811_METRICS_ENDPOINT_PUBLIC_BIND, L812_CONSOLE_LOG_IN_SERVER_CODE, L813_LOGGER_LEVEL_TRACE_OR_DEBUG, L814_DISABLE_LOG_REDACTION, L815_LOG_SQL_QUERIES_WITH_PARAMS, L816_LOG_PASSWORD_RESET_LINKS, L817_LOG_WEBHOOK_PAYLOADS, L818_LOG_FILE_UPLOAD_METADATA, L819_LOG_JWT_CLAIMS_FULL, L820_LOG_EXCEPTION_WITH_REQUEST_CONTEXT
];
