// AI & LLM Security WARN pack (A1401–A1410)
// - Single consolidated file (no subfolders).
// - Diff-first (ADDED_ONLY).
// - Low noise: only explicit integration patterns (OpenAI/Anthropic/LangChain/etc.)
//   plus clear risky wiring (raw user input into system/developer prompts,
//   client-side key usage, tool execution without allowlist markers).
// - This is WARN-only; logic-level nuance belongs to Tier 2.

const LLM_VENDOR_KEYWORDS = [
    "openai",
    "anthropic",
    "langchain",
    "langgraph",
    "llamaindex",
    "mistral",
    "cohere",
    "gemini",
    "vertexai",
    "azure openai",
];

/* -------------------------
 * A1401 — Client-side OpenAI/Anthropic key usage (explicit)
 * ------------------------- */
export const A1401_CLIENT_SIDE_LLM_API_KEY_USAGE = {
    id: "A1401_CLIENT_SIDE_LLM_API_KEY_USAGE",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "CRITICAL",
    defaultConfidence: "HIGH",

    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },

    triggerPolicy: {
        noise: "LOW",
        minimumConfidenceToEmit: "HIGH",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "window.", "localStorage", "document.", "fetch(", ...LLM_VENDOR_KEYWORDS], withinChars: 520 },
    },

    detection: {
        type: "REGEX",
        patterns: [
            // client-exposed env prefixes commonly bundled to the browser
            "(?i)\\b(NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(OPENAI|ANTHROPIC|COHERE|MISTRAL|GEMINI|VERTEX|LLM).*KEY\\b",
            // direct browser header usage patterns with vendor keys
            "(?i)Authorization\\s*:\\s*`?Bearer\\s*\\$\\{\\s*(process\\.env\\.(NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*|window\\.|localStorage\\.)",
            "(?i)x-api-key\\s*:\\s*\\$\\{\\s*(process\\.env\\.(NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*|window\\.|localStorage\\.)",
        ],
    },

    presentation: { group: "AI & LLM Security", subgroup: "Keys & Client Exposure", shortLabel: "Client key exposure", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },

    explanation: {
        title: "LLM API key may be exposed client-side",
        description: "Code suggests an LLM API key is referenced via client-exposed env vars or browser-accessible storage/headers.",
        risk: "Client-side API keys can be extracted and abused (cost blowups, data exposure, policy violations).",
        confidenceRationale: "Client env prefixes and browser contexts are explicit. Using them for API keys is a strong signal.",
        recommendation: "Move LLM calls server-side, keep keys in server-only env/secret stores, and use a backend proxy with auth + rate limiting.",
    },
};

/* -------------------------
 * A1402 — OpenAI/Anthropic SDK used in frontend bundle (explicit import)
 * ------------------------- */
export const A1402_FRONTEND_IMPORTS_LLM_SDK = {
    id: "A1402_FRONTEND_IMPORTS_LLM_SDK",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "HIGH",
    defaultConfidence: "HIGH",

    appliesTo: { fileGlobs: ["**/*.{jsx,tsx,js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },

    triggerPolicy: {
        noise: "LOW",
        minimumConfidenceToEmit: "HIGH",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["from \"openai\"", "from 'openai'", "from \"@anthropic-ai/sdk\"", "from '@anthropic-ai/sdk'", "langchain", "llamaindex"], withinChars: 420 },
    },

    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\bimport\\s+.*\\s+from\\s+['\\\"]openai['\\\"]",
            "(?i)\\bimport\\s+.*\\s+from\\s+['\\\"]@anthropic-ai/sdk['\\\"]",
            "(?i)\\brequire\\(['\\\"]openai['\\\"]\\)",
            "(?i)\\brequire\\(['\\\"]@anthropic-ai/sdk['\\\"]\\)",
        ],
    },

    presentation: { group: "AI & LLM Security", subgroup: "Keys & Client Exposure", shortLabel: "Frontend LLM SDK", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },

    explanation: {
        title: "LLM vendor SDK imported in frontend code",
        description: "Frontend code imports an LLM vendor SDK (OpenAI/Anthropic/etc.).",
        risk: "This frequently correlates with client-side API key usage and makes it easier to leak credentials or bypass server-side controls.",
        confidenceRationale: "Imports are explicit. Some apps still proxy requests, but this warrants review.",
        recommendation: "Prefer server-side SDK usage. If used client-side, ensure no secrets are embedded and enforce access via a backend proxy.",
    },
};

/* -------------------------
 * A1403 — Raw user input used in system/developer prompt (prompt injection risk)
 * ------------------------- */
export const A1403_USER_INPUT_IN_SYSTEM_OR_DEVELOPER_PROMPT = {
    id: "A1403_USER_INPUT_IN_SYSTEM_OR_DEVELOPER_PROMPT",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "HIGH",
    defaultConfidence: "MEDIUM",

    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "MEDIUM",
        minimumConfidenceToEmit: "MEDIUM",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["system", "developer", "messages", "prompt", ...LLM_VENDOR_KEYWORDS, "role:"], withinChars: 520 },
    },

    detection: {
        type: "REGEX",
        patterns: [
            // JS/TS: role: "system"/"developer" content uses req.* or userInput variable
            "(?i)role\\s*:\\s*['\\\"](system|developer)['\\\"][\\s\\S]{0,200}(content|text)\\s*:\\s*[^\\n]{0,160}(req\\.(body|query|params)|request\\.(body|query|params)|userInput|inputText|promptInput)",
            // Python-ish: system prompt f-string / format includes request args
            "(?i)(system|developer)_prompt\\s*=\\s*f?['\\\"][^'\\\"]{0,200}\\{\\s*(request\\.(args|form|json)|user_input|input_text)\\s*\\}",
        ],
    },

    presentation: { group: "AI & LLM Security", subgroup: "Prompt Injection", shortLabel: "User in system prompt", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },

    explanation: {
        title: "User input included in system/developer prompt",
        description: "Code appears to include raw user input inside a system/developer prompt message.",
        risk: "This increases prompt injection risk: user content can override instructions, leak secrets from tools/context, or manipulate tool calls.",
        confidenceRationale: "Heuristic but focused: only triggers when user input is placed into high-privilege prompt roles.",
        recommendation: "Keep system/developer prompts static. Put user input only in user messages, and apply structured templating + delimiting and tool allowlists.",
    },
};

/* -------------------------
 * A1404 — Raw user input concatenated into tool instructions (low-noise “danger zone”)
 * ------------------------- */
export const A1404_USER_INPUT_IN_TOOL_INSTRUCTIONS = {
    id: "A1404_USER_INPUT_IN_TOOL_INSTRUCTIONS",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "HIGH",
    defaultConfidence: "LOW",

    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "HIGH",
        minimumConfidenceToEmit: "LOW",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["tools", "tool", "function", "function_call", "tool_choice", "name:", "arguments", "json_schema", "zod", "langchain"], withinChars: 720 },
    },

    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["LLM_TOOLING_PRESENT", "USER_INPUT_USED_NEAR_TOOL_ARGS", "NO_ALLOWLIST_OR_VALIDATION_MARKERS_PRESENT"], withinSameHunk: true, withinLines: 240 },
    },

    presentation: { group: "AI & LLM Security", subgroup: "Tools & Actions", shortLabel: "User in tool args", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },

    explanation: {
        title: "User input may influence tool arguments without obvious validation",
        description: "LLM tool/function wiring appears to pass user input into tool arguments without obvious allowlisting/validation markers.",
        risk: "Prompt injection can drive tools to make unintended calls (SSRF, data export, destructive actions) if tool args aren’t tightly validated.",
        confidenceRationale: "Heuristic: emitted only if analyzer confirms tool wiring + user input flow + missing validation cues.",
        recommendation: "Validate tool arguments against allowlists, restrict tool set, and add server-side authorization checks for all tool actions.",
    },
};

/* -------------------------
 * A1405 — Missing moderation/content filtering toggles in LLM request wiring
 * ------------------------- */
export const A1405_LLM_REQUEST_WITHOUT_MODERATION_GUARD_MARKERS = {
    id: "A1405_LLM_REQUEST_WITHOUT_MODERATION_GUARD_MARKERS",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "MEDIUM",
    defaultConfidence: "LOW",

    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "HIGH",
        minimumConfidenceToEmit: "LOW",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["chat.completions", "responses.create", "messages", "anthropic", "langchain", "invoke", "model", "temperature"], withinChars: 720 },
    },

    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["LLM_CALL_PRESENT", "USER_GENERATED_CONTENT_PRESENT", "NO_MODERATION_OR_FILTER_MARKERS_PRESENT"], withinSameHunk: true, withinLines: 260 },
    },

    presentation: { group: "AI & LLM Security", subgroup: "Safety Controls", shortLabel: "No safety guard", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },

    explanation: {
        title: "LLM call added without obvious safety/moderation guard markers",
        description: "An LLM call appears added where user-generated content is involved, without obvious moderation/filtering guard markers in the same hunk.",
        risk: "Without safety controls, apps may generate disallowed content or leak sensitive data, and may be vulnerable to prompt injection and abuse.",
        confidenceRationale: "Heuristic: moderation can exist elsewhere; emitted only when user content + LLM call are both present nearby.",
        recommendation: "Add moderation/safety checks for user content, constrain outputs, and implement policy enforcement appropriate to your product.",
    },
};

/* -------------------------
 * A1406 — Streaming responses returned directly to client without redaction markers
 * ------------------------- */
export const A1406_STREAMED_LLM_OUTPUT_DIRECT_TO_CLIENT = {
    id: "A1406_STREAMED_LLM_OUTPUT_DIRECT_TO_CLIENT",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "MEDIUM",
    defaultConfidence: "MEDIUM",

    appliesTo: { fileGlobs: ["**/*.{js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "MEDIUM",
        minimumConfidenceToEmit: "MEDIUM",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["stream", "ReadableStream", "text/event-stream", "res.write", "SSE", "OpenAI", "anthropic"], withinChars: 720 },
    },

    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\btext/event-stream\\b",
            "(?i)\\b(res\\.write|response\\.write)\\(",
            "(?i)\\bstream\\s*:\\s*true\\b",
        ],
    },

    presentation: { group: "AI & LLM Security", subgroup: "Output Handling", shortLabel: "Streamed output", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },

    explanation: {
        title: "LLM output streamed directly to client",
        description: "Code appears to stream LLM responses to clients (SSE/streaming).",
        risk: "Streaming reduces opportunities for post-generation filtering/redaction and can leak unintended content or sensitive context.",
        confidenceRationale: "Streaming patterns are explicit, but safety controls may still exist upstream (hence WARN).",
        recommendation: "Apply output filtering/redaction, enforce tool/result allowlists, and consider buffering until safety checks pass for sensitive apps.",
    },
};

/* -------------------------
 * A1407 — Prompt includes secrets/env values (heuristic but constrained)
 * ------------------------- */
export const A1407_ENV_OR_AUTH_IN_PROMPT = {
    id: "A1407_ENV_OR_AUTH_IN_PROMPT",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "HIGH",
    defaultConfidence: "MEDIUM",

    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "MEDIUM",
        minimumConfidenceToEmit: "MEDIUM",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["prompt", "messages", "system", "developer", "content", "authorization", "cookie", "process.env", "ENV["], withinChars: 620 },
    },

    detection: {
        type: "REGEX",
        patterns: [
            "(?i)(prompt|messages)[\\s\\S]{0,220}(process\\.env\\.|ENV\\[|Authorization|authorization|Cookie|cookie|Set-Cookie|set-cookie)",
        ],
    },

    presentation: { group: "AI & LLM Security", subgroup: "Prompt Injection", shortLabel: "Secrets in prompt", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },

    explanation: {
        title: "Prompt/message construction may include secrets or auth material",
        description: "Prompt/messages appear to include environment values or authorization/cookie material.",
        risk: "Secrets included in prompts can be leaked via model outputs, logs, telemetry, or third-party retention, and can be exfiltrated through prompt injection.",
        confidenceRationale: "Heuristic, but only emitted when prompt/message wiring and auth/env markers appear together in the same hunk.",
        recommendation: "Do not include secrets in prompts. Use scoped tool access and server-side data retrieval with strict authorization checks.",
    },
};

/* -------------------------
 * A1408 — Allowing “tool execution” without explicit allowlist markers (LangChain/tool agents)
 * ------------------------- */
export const A1408_AGENT_TOOLSET_NOT_ALLOWLISTED = {
    id: "A1408_AGENT_TOOLSET_NOT_ALLOWLISTED",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "MEDIUM",
    defaultConfidence: "LOW",

    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "HIGH",
        minimumConfidenceToEmit: "LOW",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["langchain", "agent", "initializeAgentExecutor", "tools", "toolkit", "Tool", "AgentExecutor"], withinChars: 720 },
    },

    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["LANGCHAIN_AGENT_PRESENT", "TOOLS_ARRAY_PRESENT", "NO_TOOL_ALLOWLIST_MARKERS_PRESENT"], withinSameHunk: true, withinLines: 260 },
    },

    presentation: { group: "AI & LLM Security", subgroup: "Tools & Actions", shortLabel: "Agent tools", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },

    explanation: {
        title: "Agent toolset wired without obvious allowlist markers",
        description: "LangChain/agent tooling appears configured with tools, but allowlisting/validation markers are not obvious in the same hunk.",
        risk: "Agents can be steered via prompt injection to misuse tools (data export, SSRF, destructive operations) if tool scope is too broad.",
        confidenceRationale: "Heuristic: emitted only for explicit agent/tool wiring; allowlisting may exist elsewhere.",
        recommendation: "Use strict tool allowlists, validate tool arguments, and enforce server-side authorization for all tool actions.",
    },
};

/* -------------------------
 * A1409 — “Unsafe” output parsing modes or direct JSON parsing without schema (guardrails)
 * ------------------------- */
export const A1409_LLM_OUTPUT_PARSING_WITHOUT_SCHEMA_MARKERS = {
    id: "A1409_LLM_OUTPUT_PARSING_WITHOUT_SCHEMA_MARKERS",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "LOW",
    defaultConfidence: "LOW",

    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "HIGH",
        minimumConfidenceToEmit: "LOW",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["JSON.parse", "response_format", "tool", "function", "schema", "zod", "pydantic", "jsonschema", "structured"], withinChars: 720 },
    },

    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["LLM_CALL_PRESENT", "OUTPUT_JSON_PARSE_PRESENT", "NO_SCHEMA_VALIDATION_MARKERS_PRESENT"], withinSameHunk: true, withinLines: 240 },
    },

    presentation: { group: "AI & LLM Security", subgroup: "Output Handling", shortLabel: "No schema validate", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },

    explanation: {
        title: "LLM output parsed without obvious schema validation markers",
        description: "Code appears to parse LLM output as JSON without obvious schema validation markers nearby.",
        risk: "Malformed or adversarial model outputs can cause logic errors, data integrity issues, or unsafe tool argument handling.",
        confidenceRationale: "Heuristic: emitted only when LLM call + JSON parsing are both present and schema markers are absent in the same hunk.",
        recommendation: "Validate outputs with schemas (Zod/Pydantic/JSON Schema), apply strict defaults, and reject unexpected fields.",
    },
};

/* -------------------------
 * A1410 — Using user-provided URLs or HTML as LLM context (prompt injection surface)
 * ------------------------- */
export const A1410_USER_PROVIDED_URL_OR_HTML_AS_CONTEXT = {
    id: "A1410_USER_PROVIDED_URL_OR_HTML_AS_CONTEXT",
    tier: "TIER_1",
    kind: "WARN",
    category: "AI & LLM Security",
    severity: "MEDIUM",
    defaultConfidence: "LOW",

    appliesTo: { fileGlobs: ["**/*.{js,ts,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },

    triggerPolicy: {
        noise: "HIGH",
        minimumConfidenceToEmit: "LOW",
        requireSameHunk: true,
        allowSuppression: true,
        requireKeywordProximity: { keywords: ["fetch(", "axios", "requests.", "BeautifulSoup", "cheerio", "html", "markdown", "prompt", "messages", ...LLM_VENDOR_KEYWORDS], withinChars: 820 },
    },

    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["USER_CONTROLLED_URL_PRESENT", "CONTENT_FETCH_AND_INJECT_PRESENT", "LLM_CALL_PRESENT"], withinSameHunk: true, withinLines: 260 },
    },

    presentation: { group: "AI & LLM Security", subgroup: "Prompt Injection", shortLabel: "Remote context", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },

    explanation: {
        title: "User-provided URL/HTML may be injected into LLM context",
        description: "Code appears to fetch and pass remote content (URL/HTML) influenced by user input into an LLM prompt/context.",
        risk: "Remote content can carry prompt injection payloads and can also enable SSRF if URL destinations are not restricted.",
        confidenceRationale: "Heuristic: emitted only when analyzer confirms (a) user-controlled URL, (b) fetch/HTML processing, and (c) LLM call in the same hunk.",
        recommendation: "Allowlist destinations, sanitize/strip untrusted HTML, delimit untrusted context, and constrain tool access. Apply SSRF protections.",
    },
};

/* -------------------------
 * A1411 — Potential secrets sent to LLM (Legacy AI_W001)
 * ------------------------- */
export const A1411_SECRETS_IN_PROMPT_LEGACY = {
    id: "AI_W001_SECRETS_IN_PROMPT",
    tier: "TIER_1", kind: "WARN", category: "AI & LLM Security", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "LOW", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)(prompt|system_message|user_message).{0,100}(process\\.env|Authorization|cookie|secret|key)"
        ]
    },
    explanation: {
        title: "Potential secrets sent to LLM",
        description: "Prompt construction appears to include environment variables or sensitive headers.",
        risk: "Sending secrets to a third-party LLM provider can lead to data leakage and exposure of credentials to the provider or via training data if not opted out.",
        confidenceRationale: "Heuristic based on variable names and proximity; warrants review.",
        recommendation: "Ensure no sensitive credentials, keys, or private user data are included in prompts. Use placeholder values and process sensitive data locally."
    }
};

export const WARN_AI_LLM_RULES = [
    A1401_CLIENT_SIDE_LLM_API_KEY_USAGE,
    A1402_FRONTEND_IMPORTS_LLM_SDK,
    A1403_USER_INPUT_IN_SYSTEM_OR_DEVELOPER_PROMPT,
    A1404_USER_INPUT_IN_TOOL_INSTRUCTIONS,
    A1405_LLM_REQUEST_WITHOUT_MODERATION_GUARD_MARKERS,
    A1406_STREAMED_LLM_OUTPUT_DIRECT_TO_CLIENT,
    A1407_ENV_OR_AUTH_IN_PROMPT,
    A1408_AGENT_TOOLSET_NOT_ALLOWLISTED,
    A1409_LLM_OUTPUT_PARSING_WITHOUT_SCHEMA_MARKERS,
    A1410_USER_PROVIDED_URL_OR_HTML_AS_CONTEXT,
    A1411_SECRETS_IN_PROMPT_LEGACY
];
