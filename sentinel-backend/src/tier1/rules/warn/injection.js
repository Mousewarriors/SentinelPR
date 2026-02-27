/**
 * Injection WARN rules
 *
 * Philosophy:
 * - These warnings highlight common injection patterns that are often dangerous,
 *   but cannot always be proven exploitable from diff-only analysis.
 * - Keep noise low: strict caps, few annotations, and require same-hunk / keyword proximity.
 */

export const I301_SQL_STRING_CONCAT = {
    id: "I301_SQL_STRING_CONCAT",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["select", "insert", "update", "delete", "where", "from", "join", "query", "sql"], withinChars: 180 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(query|execute|raw|exec)\\b\\s*\\(.*(['\"`].*(select|insert|update|delete|where|from).*)\\+"] },
    presentation: { group: "Injection", subgroup: "SQL", shortLabel: "SQL concat", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible SQL injection risk (string concatenation)", description: "SQL appears to be constructed using string concatenation.", risk: "If user input can influence the concatenated value, this may enable SQL injection and data compromise.", confidenceRationale: "String concatenation is detectable, but static diff analysis cannot confirm whether inputs are validated or parameterized elsewhere.", recommendation: "Use parameterized queries or safe query builders. Avoid concatenating untrusted input into SQL strings." }
};

export const I302_SQL_TEMPLATE_LITERAL = {
    id: "I302_SQL_TEMPLATE_LITERAL",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["select", "where", "from", "join", "sql", "queryRaw", "execute"], withinChars: 200 }, requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: ["(?i)`[^`]*(select|insert|update|delete|where|from|join)[^`]*\\$\\{[^}]+\\}[^`]*`"],
        negativePatterns: ["(?i)(console|log|logger|print|puts|error_log)\\.", "(?i)\\bfrom\\s+[^'\"`]*\\b"]
    },
    presentation: { group: "Injection", subgroup: "SQL", shortLabel: "SQL template", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible SQL injection risk (template literal)", description: "SQL appears to be constructed using a template literal with interpolation.", risk: "If untrusted input is interpolated, this may enable SQL injection.", confidenceRationale: "Interpolation is detectable, but context (trusted vs untrusted input) cannot be proven from diff-only scanning.", recommendation: "Use parameterized queries or library-supported placeholders instead of interpolating variables into SQL." }
};

export const I303_SQL_RAW_QUERY = {
    id: "I303_SQL_RAW_QUERY",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["raw", "queryRaw", "executeRaw", "sql", "query"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(queryRaw|executeRaw|rawQuery|runRaw|execute\\s*\\(|query\\s*\\()\\b"] },
    presentation: { group: "Injection", subgroup: "SQL", shortLabel: "Raw SQL", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Raw SQL execution introduced", description: "A raw SQL execution path was added or modified.", risk: "Raw SQL increases the chance of injection if query strings are constructed unsafely.", confidenceRationale: "Raw query APIs are identifiable, but safe usage depends on parameter binding and input validation.", recommendation: "Prefer parameterized queries and ORM-safe methods. Review any raw SQL for safe binding of variables." }
};

export const I304_SQL_EXEC_DYNAMIC = {
    id: "I304_SQL_EXEC_DYNAMIC",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{py,php,rb,js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["execute", "cursor", "statement", "sql"], withinChars: 140 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bexecute\\s*\\(\\s*[^,\\)]+\\s*\\+\\s*"] },
    presentation: { group: "Injection", subgroup: "SQL", shortLabel: "Dynamic SQL", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Dynamic SQL execution detected", description: "SQL execution appears to involve dynamic string concatenation.", risk: "Dynamic SQL can enable injection if any portion is influenced by untrusted input.", confidenceRationale: "Concatenation is detectable but input provenance cannot be proven statically.", recommendation: "Bind parameters rather than concatenating. Validate and constrain any dynamic query components." }
};

export const I305_NOSQL_QUERY_FROM_REQ = {
    id: "I305_NOSQL_QUERY_FROM_REQ",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["mongo", "mongoose", "find", "query", "$where", "$regex"], withinChars: 180 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(find|findOne|aggregate|where)\\s*\\(\\s*req\\.(query|body|params)\\."] },
    presentation: { group: "Injection", subgroup: "NoSQL", shortLabel: "NoSQL input", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Possible NoSQL injection risk (query from request)", description: "A NoSQL query appears to be built directly from request input.", risk: "Passing user-controlled objects into NoSQL queries may enable operator injection (e.g., $gt, $ne) and data exposure.", confidenceRationale: "This pattern is detectable but static analysis cannot confirm input sanitization or schema validation.", recommendation: "Whitelist allowed fields and validate request inputs. Avoid passing untrusted objects directly into query builders." }
};

export const I306_MONGO_WHERE_CLAUSE = {
    id: "I306_MONGO_WHERE_CLAUSE",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\$where\\b"] },
    presentation: { group: "Injection", subgroup: "NoSQL", shortLabel: "$where", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "MongoDB $where usage introduced", description: "A MongoDB query uses $where.", risk: "$where can execute JavaScript-like expressions and has historically been associated with injection risks and performance issues.", confidenceRationale: "$where is an explicit operator and is easy to identify in code.", recommendation: "Avoid $where. Use safe query operators and indexed fields instead." }
};

export const I307_MONGO_EVAL_LIKE = {
    id: "I307_MONGO_EVAL_LIKE",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(mapReduce|eval|function\\s*\\()\\b"] },
    presentation: { group: "Injection", subgroup: "NoSQL", shortLabel: "Mongo exec", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "MongoDB execution-like feature used", description: "A MongoDB feature associated with dynamic execution or complex server-side logic was introduced.", risk: "Dynamic execution features can increase injection risk and are difficult to secure correctly.", confidenceRationale: "These keywords are detectable, but safe usage depends on how inputs are constructed.", recommendation: "Avoid dynamic execution features where possible and ensure all inputs are strictly validated and constrained." }
};

export const I308_ORM_UNSAFE_API = {
    id: "I308_ORM_UNSAFE_API",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\b\\$queryRawUnsafe\\b", "\\bunsafe\\b.*\\bquery\\b"] },
    presentation: { group: "Injection", subgroup: "ORM unsafe APIs", shortLabel: "Unsafe ORM", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Unsafe ORM API used", description: "An ORM API explicitly marked as unsafe was used.", risk: "Unsafe query APIs increase the likelihood of injection if inputs are not strictly controlled.", confidenceRationale: "The API name explicitly indicates unsafe behavior and is deterministic to detect.", recommendation: "Use safe parameterized ORM APIs and avoid unsafe/raw query helpers unless absolutely necessary." }
};

export const I309_GRAPHQL_INJECTION_RISK = {
    id: "I309_GRAPHQL_INJECTION_RISK",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["graphql", "query", "mutation", "variables"], withinChars: 200 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["GRAPHQL_QUERY_STRING_BUILT_DYNAMically", "GRAPHQL_EXECUTE_PRESENT"], withinSameHunk: true, withinLines: 80 } },
    presentation: { group: "Injection", subgroup: "GraphQL", shortLabel: "GraphQL", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "GraphQL query construction may be risky", description: "A GraphQL query appears to be constructed dynamically as a string.", risk: "Dynamic query construction can increase risk of injection-like issues or authorization bypass depending on server logic.", confidenceRationale: "GraphQL systems vary widely; dynamic strings are not always unsafe but warrant review.", recommendation: "Prefer persisted queries or structured query building. Ensure variables and authorization checks are enforced server-side." }
};

export const I310_LDAP_FILTER_CONCAT = {
    id: "I310_LDAP_FILTER_CONCAT",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["ldap", "filter", "search"], withinChars: 180 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bldap\\b.*\\b(filter|search)\\b.*\\+\\s*"] },
    presentation: { group: "Injection", subgroup: "LDAP", shortLabel: "LDAP filter", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible LDAP injection risk", description: "An LDAP filter appears to be constructed using string concatenation.", risk: "If untrusted input is concatenated into LDAP filters, attackers may alter query logic and access unauthorized data.", confidenceRationale: "Concatenation is detectable, but input validation cannot be confirmed statically.", recommendation: "Escape LDAP filter inputs and use safe query builders where available." }
};

export const I311_XPATH_CONCAT = {
    id: "I311_XPATH_CONCAT",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["xpath", "selectNodes", "evaluate"], withinChars: 160 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(xpath|selectNodes|evaluate)\\b.*\\+\\s*"] },
    presentation: { group: "Injection", subgroup: "XPath", shortLabel: "XPath", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible XPath injection risk", description: "An XPath expression appears to be constructed using string concatenation.", risk: "If user input is concatenated into XPath, attackers may manipulate queries and access unintended data.", confidenceRationale: "Concatenation is detectable but provenance of inputs is not provable in diff-only scanning.", recommendation: "Use parameterized XPath APIs or safely escape user-controlled values before inserting into XPath expressions." }
};

export const I312_SHELL_COMMAND_CONCAT = {
    id: "I312_SHELL_COMMAND_CONCAT",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,sh,bash,zsh}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["exec", "spawn", "shell", "subprocess", "system", "shell_exec"], withinChars: 200 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(exec|execSync|system|shell_exec|popen|subprocess\\.)\\b.*\\+\\s*"] },
    presentation: { group: "Injection", subgroup: "Command", shortLabel: "Cmd concat", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible command injection risk (string concatenation)", description: "A shell command appears to be constructed using string concatenation.", risk: "If user input influences the concatenated command, this may enable command injection and remote code execution.", confidenceRationale: "Concatenation is detectable, but input provenance cannot be proven from diff-only scanning.", recommendation: "Avoid shell execution when possible. Use safe APIs and pass arguments as arrays rather than concatenated strings." }
};

export const I313_SHELL_COMMAND_FROM_REQ = {
    id: "I313_SHELL_COMMAND_FROM_REQ",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(exec|execSync|system|shell_exec|popen|subprocess\\.)\\b.*req\\.(query|params|body)\\."] },
    presentation: { group: "Injection", subgroup: "Command", shortLabel: "Cmd input", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Command execution may use request input", description: "Command execution appears to directly reference request input.", risk: "Direct use of request input in command execution can lead to command injection and remote code execution.", confidenceRationale: "The sink and input reference are both present in the same expression, but sanitization may still exist elsewhere.", recommendation: "Do not pass untrusted input to shell commands. Use strict allowlists and argument arrays, or remove shell usage." }
};

export const I314_SUBPROCESS_DYNAMIC_ARGS = {
    id: "I314_SUBPROCESS_DYNAMIC_ARGS",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["subprocess", "Popen", "run", "call"], withinChars: 140 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)subprocess\\.(run|call|Popen)\\(\\s*[^\\[]"] },
    presentation: { group: "Injection", subgroup: "Command", shortLabel: "Subprocess", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Subprocess invocation may be dynamic", description: "A subprocess invocation appears to pass a dynamic command string rather than an argument list.", risk: "Dynamic command strings increase the risk of injection if any portion is user-influenced.", confidenceRationale: "The call style is detectable, but whether the source is untrusted cannot be proven statically.", recommendation: "Prefer passing commands as argument arrays and avoid shell execution. Validate and constrain all external inputs." }
};

export const I315_COMMAND_IN_YAML_CI = {
    id: "I315_COMMAND_IN_YAML_CI",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["run:", "script:", "bash", "sh", "powershell"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(run|script)\\s*:\\s*.*\\$\\{\\{\\s*github\\.event\\.|\\$\\{\\{\\s*inputs\\.|\\$\\{\\{\\s*steps\\."] },
    presentation: { group: "Injection", subgroup: "CI scripts", shortLabel: "CI var", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "CI command may interpolate untrusted input", description: "A CI script appears to interpolate event or input variables into a shell command.", risk: "CI script injection can occur if untrusted PR content influences shell execution in workflows.", confidenceRationale: "Interpolation patterns are detectable, but exploitability depends on workflow triggers and trust boundaries.", recommendation: "Avoid interpolating untrusted values into shell commands. Use safe quoting and restricted contexts; prefer non-shell actions when possible." }
};

export const I316_DESERIALIZATION_RISK = {
    id: "I316_DESERIALIZATION_RISK",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["deserialize", "pickle", "yaml.load", "unserialize", "ObjectInputStream"], withinChars: 160 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(pickle\\.loads|yaml\\.load\\(|unserialize\\(|ObjectInputStream\\b)"] },
    presentation: { group: "Injection", subgroup: "Deserialization", shortLabel: "Deserialize", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Potential unsafe deserialization", description: "A deserialization API often associated with unsafe deserialization was introduced.", risk: "Unsafe deserialization can lead to remote code execution or data tampering if attacker-controlled data is deserialized.", confidenceRationale: "The API call is detectable, but whether the input is attacker-controlled cannot be proven from diff-only scanning.", recommendation: "Avoid unsafe deserialization of untrusted data. Use safe parsers (e.g., safe YAML loaders) and validate inputs strictly." }
};

export const I317_TEMPLATE_INJECTION_RISK = {
    id: "I317_TEMPLATE_INJECTION_RISK",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["template", "render", "jinja", "twig", "handlebars", "ejs", "mustache"], withinChars: 200 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["TEMPLATE_RENDER_CALL", "TEMPLATE_STRING_FROM_REQUEST"], withinSameHunk: true, withinLines: 60 } },
    presentation: { group: "Injection", subgroup: "Template injection", shortLabel: "Template", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Possible template injection risk", description: "Template rendering appears to involve user-controlled template content.", risk: "Server-side template injection can lead to data exposure or remote code execution depending on template engine capabilities.", confidenceRationale: "Template systems vary; static analysis cannot confirm whether templates are trusted or sandboxed.", recommendation: "Do not render templates from untrusted input. Use trusted templates and pass user input only as data variables." }
};

export const I318_PATH_TRAVERSAL_JOIN_REQ = {
    id: "I318_PATH_TRAVERSAL_JOIN_REQ",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["path", "join", "readFile", "sendFile", "open", "fs."], withinChars: 200 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(join|resolve|readFile|sendFile|open)\\b\\s*\\(.*req\\.(params|query|body)\\."] },
    presentation: { group: "Injection", subgroup: "Path traversal", shortLabel: "Path", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Possible path traversal risk", description: "A file path appears to be constructed using request input.", risk: "If untrusted input influences file paths, attackers may read or write unintended files via path traversal.", confidenceRationale: "The sink and request input reference are present, but validation and normalization cannot be proven from diff-only scanning.", recommendation: "Validate and normalize paths, enforce allowlists, and avoid using request input directly in filesystem operations." }
};

export const I319_REGEX_DOS_RISKY = {
    id: "I319_REGEX_DOS_RISKY",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["regex", "RegExp", "re.compile", "match", "search"], withinChars: 200 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\([^\\)]*\\+\\)[+*]", "(\\.|\\w)\\+\\)\\+", "\\(.*\\)\\+\\+\\+"] },
    presentation: { group: "Injection", subgroup: "ReDoS", shortLabel: "Regex", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Regex may be vulnerable to catastrophic backtracking", description: "A complex regex pattern was introduced that may risk performance issues.", risk: "Catastrophic backtracking can cause denial of service if attacker-controlled input is matched.", confidenceRationale: "Heuristics can detect risky constructs but cannot confirm exploitability or input control.", recommendation: "Review regex complexity, add input length limits, and consider safer patterns or linear-time regex engines." }
};

export const I320_HEADER_INJECTION_NEWLINE = {
    id: "I320_HEADER_INJECTION_NEWLINE",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireKeywordProximity: { keywords: ["header", "setHeader", "Location", "response", "res."], withinChars: 160 }, requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)(setHeader\\(|header\\(|Location\\s*:)\\s*.*(\\r|\\n)"] },
    presentation: { group: "Injection", subgroup: "Header injection", shortLabel: "Headers", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Response header value may include newline", description: "A response header value may contain newline characters.", risk: "Newlines in header values can enable header injection or response splitting in some contexts.", confidenceRationale: "Newline usage is detectable, but impact depends on framework sanitization and runtime behavior.", recommendation: "Ensure header values are sanitized and do not include CR/LF characters. Use framework-safe APIs and validation." }
};

// I321: Prototype Pollution smell
export const I321_PROTOTYPE_POLLUTION_SMELL = {
    id: "I321_PROTOTYPE_POLLUTION_SMELL",
    tier: "TIER_1",
    kind: "WARN",
    category: "Injection",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["merge", "extend", "clone", "assign", "body"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(merge|extend|assign)\\b\\(.*req\\.(body|query|params)",
            "(\\w+)\\[(\\w+)\\]\\s*=\\s*(\\w+)\\[(\\w+)\\]"
        ]
    },
    explanation: {
        title: "Potential prototype pollution smell",
        description: "Recursive object merging or computed property assignment using request input was detected.",
        risk: "If keys like '__proto__' or 'constructor' are not filtered, an attacker can pollute the base object prototype, leading to logic bypasses or Denial of Service (DoS).",
        confidenceRationale: "Heuristic based on common vulnerable patterns in JS object manipulation.",
        recommendation: "Use safe merge libraries (e.g., lodash with protection), validate keys against an allowlist, or use Object.create(null) for data objects."
    }
};

// I322: Unsafe Reflection / Dynamic Loading
export const I322_UNSAFE_REFLECTION = {
    id: "I322_UNSAFE_REFLECTION",
    tier: "TIER_1",
    kind: "WARN",
    category: "Injection",
    severity: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireKeywordProximity: { keywords: ["require", "import", "getattr", "eval", "send"], withinChars: 120 }, requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)require\\(.*req\\.(query|params|body)",
            "(?i)import\\(.*req\\.(query|params|body)",
            "(?i)getattr\\(\\w+,\\s*req\\.(query|params|body)",
            "\\b\\w+\\[req\\.(query|params|body)\\b"
        ]
    },
    explanation: {
        title: "Unsafe reflection or dynamic loading",
        description: "Application appears to load modules or access attributes dynamically based on request input.",
        risk: "Allows attackers to access internal methods, trigger unintended logic, or potentially execute arbitrary files if they can control path parameters.",
        confidenceRationale: "Detects the use of request property values as keys for reflection or dynamic imports.",
        recommendation: "Use an allowlist to map user input to safe, predefined attributes or modules. Avoid direct reflection on the request object."
    }
};

export const I323_SSRF_NETWORK_REQUEST = {
    id: "I323_SSRF_NETWORK_REQUEST",
    tier: "TIER_1", kind: "WARN", category: "Injection", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: ["(?i)\\b(axios|requests|fetch|http)\\.(get|post|request)\\(\\s*\\w+\\s*\\)"],
        negativePatterns: [/^['"]|https?:\/\//i]
    },
    explanation: {
        title: "Potential SSRF via unsanitized network request",
        description: "A network request appears to use a direct variable as the target URL without explicit validation or allowlisting.",
        risk: "Server-Side Request Forgery (SSRF) allows attackers to force the server to make requests to internal resources or external malicious sites.",
        recommendation: "Validate URLs against a strict allowlist of domains and protocols. Avoid passing raw user input into network request sinks."
    }
};

export const I324_SSL_VERIFY_DISABLED = {
    id: "I324_SSL_VERIFY_DISABLED",
    tier: "TIER_1", kind: "FAIL", category: "Security", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{py,js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    detection: {
        type: "REGEX",
        patterns: ["(?i)verify\\s*[:=]\\s*False", "(?i)rejectUnauthorized\\s*[:=]\\s*false"]
    },
    explanation: {
        title: "SSL certificate verification disabled",
        description: "SSL/TLS certificate verification is explicitly disabled, making the connection vulnerable to Man-in-the-Middle (MitM) attacks.",
        risk: "An attacker could intercept or modify traffic between your application and the remote server.",
        recommendation: "Never disable SSL verification in production. Ensure valid certificates are used and trusted."
    }
};

export const I325_NETWORK_TIMEOUT_MISSING = {
    id: "I325_NETWORK_TIMEOUT_MISSING",
    tier: "TIER_1", kind: "WARN", category: "Security", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{py,js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM" },
    detection: {
        type: "REGEX",
        patterns: ["(?i)\\b(axios|requests|fetch|http)\\.(get|post|request)\\("],
        negativePatterns: [/\btimeout\b/i]
    },
    explanation: {
        title: "Network request without timeout",
        description: "A network request is initiated without an explicit timeout setting.",
        risk: "Slow or hung responses from the remote server can cause your application to hang, potentially leading to denial-of-service (DoS) or resource exhaustion.",
        recommendation: "Always specify reasonable timeout values for all network operations."
    }
};

export const WARN_INJECTION_RULES = [
    I301_SQL_STRING_CONCAT, I302_SQL_TEMPLATE_LITERAL, I303_SQL_RAW_QUERY, I304_SQL_EXEC_DYNAMIC, I305_NOSQL_QUERY_FROM_REQ, I306_MONGO_WHERE_CLAUSE, I307_MONGO_EVAL_LIKE, I308_ORM_UNSAFE_API, I309_GRAPHQL_INJECTION_RISK, I310_LDAP_FILTER_CONCAT, I311_XPATH_CONCAT, I312_SHELL_COMMAND_CONCAT, I313_SHELL_COMMAND_FROM_REQ, I314_SUBPROCESS_DYNAMIC_ARGS, I315_COMMAND_IN_YAML_CI, I316_DESERIALIZATION_RISK, I317_TEMPLATE_INJECTION_RISK, I318_PATH_TRAVERSAL_JOIN_REQ, I319_REGEX_DOS_RISKY, I320_HEADER_INJECTION_NEWLINE, I323_SSRF_NETWORK_REQUEST, I324_SSL_VERIFY_DISABLED, I325_NETWORK_TIMEOUT_MISSING
];
