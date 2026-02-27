import fs from 'fs';
import { StaticAnalyzer } from './staticAnalyzer.js';

async function runVerification() {
    const analyzer = new StaticAnalyzer();
    const filePath = './scanner-fixtures/rule-enhancements/test_triplets.js';
    const content = fs.readFileSync(filePath, 'utf8');

    // Simulate a diff where the entire file added
    const diff = `--- a/test_triplets.js\n+++ b/test_triplets.js\n@@ -1,35 +1,35 @@\n` +
        content.split('\n').map(line => '+' + line).join('\n');

    console.log("Running enhancement verification...");
    const results = analyzer.analyzeDiff(diff);

    const findings = results.findings;
    const ruleIds = findings.map(f => f.ruleId);

    console.log("\n--- Findings Detected ---");
    findings.forEach(f => console.log(`[${f.severity}] ${f.ruleId}: ${f.title || f.ruleId} (Line ${f.line})\n    > ${f.description || 'No description'}`));

    const expectedFailures = ["S004", "SSL001", "DESER001"];
    const expectedWarnings = ["W101_POSSIBLE_SECRET_VAR_ASSIGN", "M001_SECRET_LOGGING_CORRELATION"];

    console.log("\n--- Verification Report ---");

    // Check for expected FAIL rules
    expectedFailures.forEach(id => {
        const found = findings.some(f => f.ruleId === id);
        console.log(`${found ? '✅' : '❌'} Expected FAIL rule [${id}] triggered: ${found}`);
    });

    // Check for expected WARN rules
    expectedWarnings.forEach(id => {
        const found = findings.some(f => f.ruleId === id);
        console.log(`${found ? '✅' : '❌'} Expected WARN rule [${id}] triggered: ${found}`);
    });

    // Check for correct filtering (Line 5 should be skipped)
    const line5Finding = findings.find(f => f.line === 5);
    console.log(`${!line5Finding ? '✅' : '❌'} Comment filter (Line 5) working: ${!line5Finding}`);

    // Check for Guard logic (Line 19 should be skipped/lowered)
    const line19Finding = findings.find(f => f.line === 19);
    console.log(`${!line19Finding ? '✅' : '❌'} Guard filter (Line 19) working: ${!line19Finding}`);

    if (findings.length > 0) {
        process.exit(0);
    } else {
        process.exit(1);
    }
}

runVerification().catch(err => {
    console.error(err);
    process.exit(1);
});
