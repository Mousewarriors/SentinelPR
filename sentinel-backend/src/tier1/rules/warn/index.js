import { WARN_SECRETS_RULES } from "./secrets.js";
import { WARN_AUTH_RULES } from "./auth.js";
import { WARN_INJECTION_RULES } from "./injection.js";
import { WARN_CI_RULES } from "./ci.js";
import { WARN_DEPS_RULES } from "./deps.js";
import { WARN_CRYPTO_RULES } from "./crypto.js";
import { WARN_LOGGING_RULES } from "./logging.js";
import { WARN_FILES_RULES } from "./files.js";
import { WARN_WEB_RULES } from "./web.js";
import { WARN_GDPR_RULES } from "./gdpr.js";
import { WARN_SERVERLESS_RULES } from "./serverless.js";
import { WARN_IAC_RULES } from "./iac.js";
import { WARN_AI_LLM_RULES } from "./ai_llm.js";
import { CORRELATION_RULES } from "./meta.js";

export const TIER1_WARN_RULES = [
    ...WARN_SECRETS_RULES,
    ...WARN_AUTH_RULES,
    ...WARN_INJECTION_RULES,
    ...WARN_CI_RULES,
    ...WARN_DEPS_RULES,
    ...WARN_CRYPTO_RULES,
    ...WARN_LOGGING_RULES,
    ...WARN_FILES_RULES,
    ...WARN_WEB_RULES,
    ...WARN_GDPR_RULES,
    ...WARN_SERVERLESS_RULES,
    ...WARN_IAC_RULES,
    ...WARN_AI_LLM_RULES,
    ...CORRELATION_RULES
];

// Map for quick access by ID
export const TIER1_WARN_RULES_BY_ID = new Map(
    TIER1_WARN_RULES.map(rule => [rule.id, rule])
);
