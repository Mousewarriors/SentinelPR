All analysis output MUST be valid JSON and conform exactly to the following schema.
Do not include markdown, comments, or conversational text outside the JSON object.

Schema:

{
  "verdict": "PASS" | "WARN" | "FAIL",
  "summary": "string",
  "findings": [
    {
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "confidence": "HIGH" | "MEDIUM" | "LOW",
      "title": "string",
      "description": "string",
      "evidence": {
        "snippet": "string",
        "reasoning": "string",
        "impact_scenario": "string"
      },
      "location": {
        "path": "string",
        "start_line": number,
        "end_line": number
      },
      "recommended_fix": "string"
    }
  ]
}

Rules:
- Always return a JSON object matching this schema.
- If no issues are found, return an empty findings array.
- Do not include fields not defined in the schema.
- Do not include null values; omit findings instead.

Summary rules:
- Must be a single sentence.
- Must not include recommendations or speculative language.
- Must deterministically reflect the verdict.
  - PASS: No security issues identified.
  - WARN: Security issues identified that require attention.
  - FAIL: Security issues identified that require remediation.