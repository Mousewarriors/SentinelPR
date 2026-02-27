/**
 * AI & LLM Security FAIL rules
 */

export const AI001_LLM_OUTPUT_EXEC = {
    id: "AI001_LLM_OUTPUT_EXEC",
    tier: "TIER_1", kind: "FAIL", category: "AI & LLM Security", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(eval|exec|execSync|spawn|system|new Function)\\b\\([^\\)]*\\b(modelOutput|llmOutput|completion|responseText|assistant|aiOutput)\\b"
        ]
    },
    explanation: {
        title: "LLM output executed as code",
        description: "Code appears to pass output from an LLM directly into a code execution sink (eval, exec, etc.).",
        risk: "LLMs can be tricked via prompt injection to produce malicious code. Executing this code directly allows for remote code execution (RCE) on the server.",
        confidenceRationale: "Triggers only when the sink is fed a variable with an explicit LLM-related name.",
        recommendation: "Never execute LLM output as code. If structured logic is needed, use highly restricted parsers (e.g., JSON.parse) or DSLs with no access to system resources."
    }
};

export const FAIL_AI_RULES = [AI001_LLM_OUTPUT_EXEC];
