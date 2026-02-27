/**
 * Serverless & Cloud Functions WARN rules
 */

export const S1106_CLOUDWATCH_LOGS_DATA_EXPOSURE = {
    id: "S1106_CLOUDWATCH_LOGS_DATA_EXPOSURE",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars,js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["cloudwatch", "logs", "logGroup", "retention", "console.log", "logger", "print", "puts"], withinChars: 420 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["SERVERLESS_FUNCTION_PRESENT", "LOGGING_CALL_PRESENT", "SENSITIVE_FIELD_NAME_PRESENT"], withinSameHunk: true, withinLines: 220 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Logging", shortLabel: "Sensitive logs", maxFindingsPerPR: 1, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: {
        title: "Function logging may include sensitive data",
        description: "A change adds logging in a serverless function where sensitive fields may be present.",
        risk: "Tokens, cookies, and PII can end up in centralized logs.",
        confidenceRationale: "Heuristic: sensitive field names near a logging call.",
        recommendation: "Redact sensitive fields before logging."
    },
};

export const S1107_FUNCTION_ENV_CONTAINS_SECRET_KEYWORDS = {
    id: "S1107_FUNCTION_ENV_CONTAINS_SECRET_KEYWORDS",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars,env,properties,ini,toml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["environment", "env", "variables", "lambda", "function", "vercel", "netlify"], withinChars: 520 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY|AWS_SECRET_ACCESS_KEY)\\b\\s*[:=]"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Secrets", shortLabel: "Env secrets", maxFindingsPerPR: 3, includeInSummary: true },
    explanation: {
        title: "Function env contains secret-like variables",
        description: "Environment configuration includes variables named like secrets.",
        risk: "Secrets in env increase exposure via logs and debug tooling.",
        confidenceRationale: "Variable names are explicit.",
        recommendation: "Prefer managed secret stores."
    },
};

export const S1109_FUNCTION_TIMEOUT_VERY_HIGH = {
    id: "S1109_FUNCTION_TIMEOUT_VERY_HIGH",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["timeout", "lambda", "function"], withinChars: 420 } },
    detection: { type: "REGEX", patterns: ["(?i)\\btimeout\\s*[:=]\\s*(60|[6-9]\\d|\\d{3,})\\b", "(?i)Timeout\\s*:\\s*(60|[6-9]\\d|\\d{3,})\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Limits", shortLabel: "High timeout", maxFindingsPerPR: 2, includeInSummary: true },
    explanation: {
        title: "Function timeout set very high",
        description: "A function timeout appears set to a high value (≥60s).",
        risk: "High timeouts increase DoS/cost exposure.",
        confidenceRationale: "Explicit values.",
        recommendation: "Keep timeouts minimal."
    },
};

export const S1110_FUNCTION_MEMORY_VERY_HIGH = {
    id: "S1110_FUNCTION_MEMORY_VERY_HIGH",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["memory", "memorySize", "lambda"], withinChars: 420 } },
    detection: { type: "REGEX", patterns: ["(?i)memory(Size)?\\s*[:=]\\s*(3072|4096|[5-9]\\d{3,}|\\d{5,})\\b", "(?i)MemorySize\\s*:\\s*(3072|4096|[5-9]\\d{3,}|\\d{5,})\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Limits", shortLabel: "High memory", maxFindingsPerPR: 1, includeInSummary: false },
    explanation: {
        title: "Function memory allocation unusually high",
        description: "Function memory appears set to a high value.",
        risk: "Higher memory increases cost blast radius.",
        confidenceRationale: "Explicit values.",
        recommendation: "Profile workload and set memory appropriately."
    },
};

export const S1112_VERCEL_NO_AUTH_MIDDLEWARE = {
    id: "S1112_VERCEL_NO_AUTH_MIDDLEWARE",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/api/**/*.{js,ts,jsx,tsx}", "**/pages/api/**/*.{js,ts,jsx,tsx}", "**/app/api/**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["SERVERLESS_HANDLER_PRESENT", "NO_AUTH_MARKER_KEYWORDS_PRESENT_NEARBY"], withinSameHunk: true, withinLines: 200 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Endpoints", shortLabel: "New endpoint", maxFindingsPerPR: 1, includeInSummary: false },
    explanation: {
        title: "New serverless endpoint without obvious auth marker",
        description: "A serverless handler was introduced without obvious auth markers nearby.",
        risk: "Missing auth checks can lead to unauthorized access.",
        confidenceRationale: "Heuristic: auth may be applied elsewhere.",
        recommendation: "Confirm the handler is protected."
    },
};

export const S1118_SAM_VPC_EGRESS_WIDE = {
    id: "S1118_SAM_VPC_EGRESS_WIDE",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["LAMBDA_VPC_CONFIG_PRESENT", "SECURITY_GROUP_EGRESS_WIDE_OPEN_PRESENT"], withinSameHunk: true, withinLines: 260 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Networking", shortLabel: "Egress wide", maxFindingsPerPR: 1, includeInSummary: false },
    explanation: {
        title: "Function in VPC with wide-open egress",
        description: "A function is configured in a VPC with broad egress settings.",
        risk: "Wide egress increases exfiltration blast radius.",
        confidenceRationale: "Composite detection of VPC config and wide SG egress.",
        recommendation: "Restrict egress where practical."
    },
};

export const S1119_DLQ_MISSING_FOR_ASYNC = {
    id: "S1119_DLQ_MISSING_FOR_ASYNC",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["ASYNC_INVOCATION_CONFIG_PRESENT", "NO_FAILURE_DESTINATION_PRESENT"], withinSameHunk: true, withinLines: 260 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Reliability", shortLabel: "DLQ missing", maxFindingsPerPR: 1, includeInSummary: false },
    explanation: {
        title: "Async trigger without obvious failure destination",
        description: "Async invocation configuration lacks an obvious DLQ/on-failure destination.",
        risk: "Dropped failures can hide security-impacting gaps.",
        confidenceRationale: "Heuristic based on config patterns.",
        recommendation: "Add DLQ/on-failure destinations."
    },
};

export const S1120_BROAD_EVENT_TRIGGER = {
    id: "S1120_BROAD_EVENT_TRIGGER",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["EVENT_SOURCE_MAPPING_PRESENT", "NO_FILTERING_PRESENT_OR_WILDCARD_PRESENT"], withinSameHunk: true, withinLines: 260 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Triggers", shortLabel: "Broad trigger", maxFindingsPerPR: 1, includeInSummary: false },
    explanation: {
        title: "Event trigger may be overly broad",
        description: "An event trigger lacks obvious scoping or filtering.",
        risk: "Broad triggers increase attack surface and unexpected invocations.",
        confidenceRationale: "Heuristic logic.",
        recommendation: "Add trigger scoping/filters."
    },
};

export const S1123_CLOUD_RUN_LATEST_TAG = {
    id: "S1123_CLOUD_RUN_LATEST_TAG",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bimage\\s*[:=]\\s*[^\\s'\"]+:latest\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Supply chain", shortLabel: "Image :latest", maxFindingsPerPR: 2, includeInSummary: true },
    explanation: {
        title: "Cloud Run image uses :latest tag",
        description: "A Cloud Run container image reference uses the mutable `:latest` tag.",
        risk: "Mutable tags reduce reproducibility and can introduce unreviewed changes.",
        confidenceRationale: "Explicit `:latest` tag.",
        recommendation: "Pin to a versioned tag or digest."
    },
};

export const S1124_LAMBDA_IMAGE_NOT_PINNED = {
    id: "S1124_LAMBDA_IMAGE_NOT_PINNED",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "COMPOSITE", composite: { allOf: ["LAMBDA_CONTAINER_IMAGE_REFERENCE_PRESENT", "IMAGE_REFERENCE_HAS_NO_DIGEST"], withinSameHunk: true, withinLines: 120 } },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Supply chain", shortLabel: "Unpinned image", maxFindingsPerPR: 1, includeInSummary: true },
    explanation: {
        title: "Lambda container image not pinned to digest",
        description: "A Lambda container image reference lacks an immutable digest.",
        risk: "Mutable tags can change contents without review.",
        confidenceRationale: "Composite check for missing digest.",
        recommendation: "Pin images by digest."
    },
};

export const S1128_LAMBDA_HIGH_TMP_STORAGE = {
    id: "S1128_LAMBDA_HIGH_TMP_STORAGE",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "LOW", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)EphemeralStorage[\\s\\S]{0,120}Size\\s*:\\s*(5120|[6-9]\\d{3,}|\\d{5,})\\b", "(?i)ephemeral_storage\\s*\\{[\\s\\S]{0,160}size\\s*=\\s*(5120|[6-9]\\d{3,}|\\d{5,})\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Limits", shortLabel: "High /tmp", maxFindingsPerPR: 1, includeInSummary: false },
    explanation: {
        title: "Lambda ephemeral storage unusually high",
        description: "Ephemeral storage (/tmp) appears configured to a high value (≥5120 MB).",
        risk: "Large storage can enable disk-heavy abuse patterns.",
        confidenceRationale: "Explicit values.",
        recommendation: "Confirm high /tmp is required."
    },
};

export const S1129_GCP_MAX_INSTANCES_HIGH = {
    id: "S1129_GCP_MAX_INSTANCES_HIGH",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bmaxInstances\\s*[:=]\\s*(100|[1-9]\\d{2,}|\\d{4,})\\b", "(?i)\\bmax_instance_count\\s*=\\s*(100|[1-9]\\d{2,}|\\d{4,})\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Limits", shortLabel: "High scale", maxFindingsPerPR: 1, includeInSummary: true },
    explanation: {
        title: "Max instances appears very high",
        description: "A scaling limit for a function appears set very high (≥100).",
        risk: "High scaling limits increase cost exposure under abuse.",
        confidenceRationale: "Explicit values.",
        recommendation: "Set realistic scaling limits."
    },
};

export const S1130_LAMBDA_LONG_LOG_RETENTION = {
    id: "S1130_LAMBDA_LONG_LOG_RETENTION",
    tier: "TIER_1", kind: "WARN", category: "Serverless & Cloud Functions", severity: "LOW", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json,tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bretention(InDays)?\\s*[:=]\\s*(365|[4-9]\\d{2,}|\\d{4,})\\b"] },
    presentation: { group: "Serverless & Cloud Functions", subgroup: "Logging", shortLabel: "Long retention", maxFindingsPerPR: 2, includeInSummary: true },
    explanation: {
        title: "Log retention set very long",
        description: "Log retention appears configured to a very long period (≥365 days).",
        risk: "Long retention increases sensitive data exposure blast radius.",
        confidenceRationale: "Explicit values.",
        recommendation: "Set retention to the minimum operational period."
    },
};

export const WARN_SERVERLESS_RULES = [
    S1106_CLOUDWATCH_LOGS_DATA_EXPOSURE,
    S1107_FUNCTION_ENV_CONTAINS_SECRET_KEYWORDS,
    S1109_FUNCTION_TIMEOUT_VERY_HIGH,
    S1110_FUNCTION_MEMORY_VERY_HIGH,
    S1112_VERCEL_NO_AUTH_MIDDLEWARE,
    S1118_SAM_VPC_EGRESS_WIDE,
    S1119_DLQ_MISSING_FOR_ASYNC,
    S1120_BROAD_EVENT_TRIGGER,
    S1123_CLOUD_RUN_LATEST_TAG,
    S1124_LAMBDA_IMAGE_NOT_PINNED,
    S1128_LAMBDA_HIGH_TMP_STORAGE,
    S1129_GCP_MAX_INSTANCES_HIGH,
    S1130_LAMBDA_LONG_LOG_RETENTION
];
