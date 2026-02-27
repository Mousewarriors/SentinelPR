import { FAIL_SERVERLESS_RULES } from "./serverless.js";
import { FAIL_IAC_RULES } from "./iac.js";
import { FAIL_AI_RULES } from "./ai.js";
import { FAIL_WEB_RULES } from "./web.js";
import { FAIL_FILES_RULES } from "./files.js";
import { FAIL_SECRETS_RULES } from "./secrets.js";
import { FAIL_AUTH_RULES } from "./auth.js";
import { FAIL_INJECTION_RULES } from "./injection.js";
import { FAIL_CRYPTO_RULES } from "./crypto.js";
import { FAIL_XSS_RULES } from "./xss.js";
import { FAIL_JAVA_RULES } from "./lang/java.js";
import { FAIL_GO_RULES } from "./lang/go.js";
import { FAIL_DOTNET_RULES } from "./lang/dotnet.js";

/**
 * Global TIER 1 FAIL Rules Registry
 */

export const S001_PRIVATE_KEY = {
    id: "S001", severity: "CRITICAL", title: "Private key committed", category: "Secrets & Credentials",
    appliesTo: { fileGlobs: ["**/*"], excludeGlobs: ["**/*.md", "**/docs/**", "**/examples/**", "**/tests/**"] },
    detection: {
        type: "REGEX",
        patterns: [/-----BEGIN RSA PRIVATE KEY-----/, /-----BEGIN EC PRIVATE KEY-----/, /-----BEGIN PRIVATE KEY-----/, /-----BEGIN OPENSSH PRIVATE KEY-----/],
        negativePatterns: [/REDACTED/i, /example/i]
    },
    explanation: {
        title: "Private key committed",
        description: "A private key was found in the repository. SSL/SSH/EC/RSA keys should never be committed to source control.",
        risk: "Allows an attacker to decrypt traffic, impersonate the server, or gain unauthorized access to infrastructure.",
        recommendation: "Rotate the key immediately. Use a secret manager (AWS Secrets Manager, GCP Secret Manager) instead."
    }
};

export const S004_GITHUB_TOKEN = {
    id: "S004", severity: "CRITICAL", title: "GitHub authentication token committed", category: "Secrets & Credentials",
    appliesTo: { fileGlobs: ["**/*"], excludeGlobs: ["**/*.md", "**/docs/**", "**/examples/**", "**/tests/**"] },
    detection: {
        type: "REGEX",
        patterns: [/ghp_[A-Za-z0-9]{36,}/, /github_pat_[A-Za-z0-9_]{20,}/, /gho_[A-Za-z0-9]{20,}/, /ghu_[A-Za-z0-9]{20,}/, /ghs_[A-Za-z0-9]{20,}/, /ghr_[A-Za-z0-9]{20,}/],
        negativePatterns: [/REDACTED/i, /your_token/i, /example/i]
    },
    explanation: {
        title: "GitHub authentication token committed",
        description: "A GitHub Personal Access Token (PAT) was detected in the repository.",
        risk: "Allows an attacker to access GitHub repositories, organizations, and actions on behalf of the user or system.",
        recommendation: "Revoke the token in GitHub Settings immediately. Use GitHub Apps or environment-based auth."
    }
};

export const SSL001_TLS_VERIFY_DISABLED = {
    id: "SSL001", severity: "CRITICAL", title: "TLS verification disabled in production", category: "Encryption",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**"], excludeGlobs: ["**/tests/**", "**/examples/**"] },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["SSL_VERIFY_DISABLED", "IS_PROD_CONTEXT"] }
    }
};

export const DESER001_INSECURE_DESERIALIZATION = {
    id: "DESER001", severity: "CRITICAL", title: "Insecure deserialization of request input", category: "Injection",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], excludeGlobs: ["**/tests/**"] },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["DESERIALIZATION_SINK", "HAS_NEAR_SOURCE"] }
    }
};

export const TIER1_FAIL_RULES = [
    S001_PRIVATE_KEY,
    S004_GITHUB_TOKEN,
    SSL001_TLS_VERIFY_DISABLED,
    DESER001_INSECURE_DESERIALIZATION,
    ...FAIL_SERVERLESS_RULES,
    ...FAIL_IAC_RULES,
    ...FAIL_AI_RULES,
    ...FAIL_WEB_RULES,
    ...FAIL_FILES_RULES,
    ...FAIL_SECRETS_RULES,
    ...FAIL_AUTH_RULES,
    ...FAIL_INJECTION_RULES,
    ...FAIL_CRYPTO_RULES,
    ...FAIL_XSS_RULES,
    ...FAIL_JAVA_RULES,
    ...FAIL_GO_RULES,
    ...FAIL_DOTNET_RULES
];

export const TIER1_FAIL_RULES_BY_ID = new Map(
    TIER1_FAIL_RULES.map(rule => [rule.id, rule])
);
