# SentinelPR Rules Guidelines

To maintain consistency and allow for reliable automation, all security rules must follow this structure.

## 1. Directory Structure

- **FAIL Rules**: `src/tier1/rules/fail/`
  - High-confidence, deterministic rules that should stop a PR.
  - Severity: `CRITICAL` or `HIGH`.
  - Kind: `FAIL`.
- **WARN Rules**: `src/tier1/rules/warn/`
  - Advisory rules, heuristics, or maturity signals.
  - Severity: `MEDIUM` or `LOW`.
  - Kind: `WARN`.

## 2. File Formatting

- **Consolidated Files**: Rules are grouped by category into a single `.js` file per category (e.g., `secrets.js`, `iac.js`, `serverless.js`).
- **No Subfolders**: Do not create subdirectories for individual rules (e.g., avoid `warn/serverless/rule.js`).
- **Exports**: Each file must export named rule objects and a final array containing all rules in that file.

### Example: `src/tier1/rules/fail/serverless.js`
```javascript
export const SF001_PUBLIC_EXPOSURE = {
    id: "SF001_PUBLIC_EXPOSURE",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Serverless",
    severity: "CRITICAL",
    // ... other fields
};

export const FAIL_SERVERLESS_RULES = [
    SF001_PUBLIC_EXPOSURE
];
```

## 3. Rule Object Schema

Each rule object must include:
- `id`: Unique alphanumeric ID (e.g., `SF001`, `S1106`).
- `tier`: Usually `TIER_1`.
- `kind`: `FAIL` or `WARN`.
- `category`: The functional security domain.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `appliesTo`: File globs, scan mode (`DIFF`), and target lines (`ADDED_ONLY`).
- `triggerPolicy`: Noise levels and keyword proximity requirements.
- `detection`: `REGEX` or `COMPOSITE`.
- `presentation`: UI-related metadata.
- `explanation`: Title, description, risk, and recommendation.

## 4. Confidence vs. Severity

- **FAIL**: Use for issues where we have high confidence and high impact. No speculation.
- **WARN**: Use for "suggestive" patterns or where the fix is advisory rather than mandatory for security.

## 5. Integration

- Import new category files into the respective `index.js` (in `fail/` or `warn/`).
- Spread the category array into the global registry (`TIER1_FAIL_RULES` or `TIER1_WARN_RULES`).
- Update the `index.js` Map to include the new rules for ID lookup.
