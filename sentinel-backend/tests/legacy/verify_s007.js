import { StaticAnalyzer } from './staticAnalyzer.js';
import assert from 'assert';

const analyzer = new StaticAnalyzer();
const diffText = `diff --git a/cfg.py b/cfg.py
--- a/cfg.py
+++ b/cfg.py
@@ -1,5 +1,6 @@
+aws_access_key_id = 'AKIA1234567890ABCDEF'
+aws_secret_access_key = 'abcd1234efgh5678ijkl9012mnop3456qrst7890'`;

const result = analyzer.analyzeDiff(diffText);
const finding = result.findings[0];

console.log("--- Inspected Finding (S007) ---");
console.log(JSON.stringify(finding, null, 2));

const mandatoryFields = ["title", "description", "risk", "confidenceRationale", "recommendation"];
mandatoryFields.forEach(field => {
    assert(finding[field], `Missing mandatory field: ${field}`);
});

console.log("\n✅ S007 finding has all mandatory fields.");
