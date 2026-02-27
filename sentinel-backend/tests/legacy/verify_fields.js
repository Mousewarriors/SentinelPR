import { StaticAnalyzer } from './staticAnalyzer.js';
import assert from 'assert';

const analyzer = new StaticAnalyzer();
const diffText = `diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -1,1 +1,1 @@
+eval(data);`;

const result = analyzer.analyzeDiff(diffText);
const finding = result.findings[0];

console.log("--- Inspected Finding ---");
console.log(JSON.stringify(finding, null, 2));

const mandatoryFields = ["title", "description", "risk", "confidenceRationale", "recommendation"];
mandatoryFields.forEach(field => {
    assert(finding[field], `Missing mandatory field: ${field}`);
    assert(typeof finding[field] === 'string' && finding[field].length > 0, `Field ${field} must be a non-empty string`);
});

console.log("\n✅ All mandatory explanatory fields are present and populated.");
