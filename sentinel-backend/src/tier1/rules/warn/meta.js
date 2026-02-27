export const M001_SECRET_LOGGING_CORRELATION = {
    id: "M001_SECRET_LOGGING_CORRELATION",
    tier: "TIER_1", kind: "WARN", category: "Correlation", severity: "HIGH",
    correlation: {
        requires: ["W101_POSSIBLE_SECRET_VAR_ASSIGN", "L801_LOG_SECRETS_TOKENS"],
        logic: "BOTH_PRESENT"
    },
    explanation: {
        title: "High Risk: Secrets found near logging calls",
        description: "Potential secrets were detected in the same hunk or file as commands that log environment or variable state.",
        risk: "The combination of hardcoded secrets and verbose logging significantly increases the probability of credentials leaking into log management systems.",
        recommendation: "Review the detected logging calls (W116) and ensure the secret (W101) is not being dumped into the output."
    }
};

export const M002_INJECTION_SINK_PLUS_USER_SOURCE = {
    id: "M002_INJECTION_SINK_PLUS_USER_SOURCE",
    tier: "TIER_1", kind: "WARN", category: "Correlation", severity: "CRITICAL",
    correlation: {
        requires: ["PATH001_USER_CONTROLLED_FILE_IO", "HAS_NEAR_SOURCE"],
        logic: "BOTH_PRESENT"
    },
    explanation: {
        title: "High Confidence: Path Traversal Sink linked to User Input",
        description: "A dangerous I/O sink was found directly linked to an unvalidated request source.",
        risk: "This is a high-confidence path traversal vulnerability that could allow an attacker to read or write arbitrary files on the server.",
        recommendation: "Use path.basename() or a strict allowlist to sanitize the input before passing it to I/O functions."
    }
};

export const CORRELATION_RULES = [M001_SECRET_LOGGING_CORRELATION, M002_INJECTION_SINK_PLUS_USER_SOURCE];
