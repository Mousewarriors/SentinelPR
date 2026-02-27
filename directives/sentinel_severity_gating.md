Severity and verdict gating rules:

Verdict determination:
- If any finding has severity CRITICAL or HIGH:
  verdict MUST be "FAIL"
- Else if any finding has severity MEDIUM:
  verdict MUST be "WARN"
- Else:
  verdict MUST be "PASS"

Severity and confidence consistency:
- CRITICAL findings MUST have HIGH confidence.
- HIGH findings MUST have at least MEDIUM confidence.
- If confidence is LOW, severity MUST NOT exceed MEDIUM.

These rules are mandatory and must never be overridden.