import { runTier1Analysis } from "./staticAnalyzer.js";
import fs from 'fs';

const sampleDiff = fs.readFileSync('./fixtures/injection_full_test.diff', 'utf8');

const findings = runTier1Analysis(sampleDiff);

console.log("--- Tier 1 Injection FAIL Analysis Result ---");
console.log(`Total Findings: ${findings.length}`);

const failFindings = findings.filter(f => f.kind === "FAIL");
const warnFindings = findings.filter(f => f.kind === "WARN");

console.log(`FAIL Findings: ${failFindings.length}`);
console.log(`WARN Findings: ${warnFindings.length}`);

console.log("\ndetails of FAIL findings:");
failFindings.forEach(f => {
    console.log(`[${f.ruleId}] Line ${f.line}: ${f.title}`);
    console.log(`Snippet: ${f.snippet}`);
});

function determineVerdict(findings) {
    if (findings.some(f => f.kind === "FAIL")) return "FAIL";
    if (findings.length > 0) return "WARN";
    return "PASS";
}

const verdict = determineVerdict(findings);
console.log(`\nGlobal Verdict: ${verdict}`);

// We expect at least these rule IDs to fire: SQL001, SQL002, SQL003, SQL004, NOSQL001, NOSQL002, NOSQL003
// Note: SQL004 overlaps with SQL001/002, so some lines might have multiple findings.
const expectedFailRuleIds = [
    "SQL001_TEMPLATE_TO_QUERY",
    "SQL002_CONCAT_TO_QUERY",
    "SQL003_UNSAFE_RAW_SQL_API",
    "SQL004_REQ_INPUT_IN_QUERY",
    "NOSQL001_OPERATOR_INJECTION",
    "NOSQL002_DYNAMIC_FIELD_QUERY",
    "NOSQL003_JSON_PARSE_IN_QUERY"
];

const firedFailRuleIds = new Set(failFindings.map(f => f.ruleId));
const missingRules = expectedFailRuleIds.filter(id => !firedFailRuleIds.has(id));

if (verdict === "FAIL" && missingRules.length === 0) {
    console.log("\n✅ Test Passed: All expected Injection FAIL rules triggered.");
} else {
    console.log(`\n❌ Test Failed: Some expected FAIL rules did not trigger: ${missingRules.join(", ")}`);
    process.exit(1);
}
