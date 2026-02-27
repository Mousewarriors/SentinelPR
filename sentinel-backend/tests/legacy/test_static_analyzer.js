import { runTier1Analysis } from "./staticAnalyzer.js";

const sampleDiff = `
diff --git a/.env.example b/.env.example
index e69de29..4982343 100644
--- a/.env.example
+++ b/.env.example
@@ -0,0 +1,2 @@
+GITHUB_TOKEN=ghp_redacted_test_token_1234567890
+STRIPE_KEY=sk_live_redacted_test_key_1234567890
diff --git a/app.js b/app.js
index e69de29..e123456 100644
--- a/app.js
+++ b/app.js
@@ -10,1 +10,3 @@
+const data = eval(req.body.data);
+db.query("SELECT * FROM users WHERE id = " + req.query.id);
+const config = yaml.load(fs.readFileSync('config.yml'));
`;

const findings = runTier1Analysis(sampleDiff);

console.log("--- Tier 1 Analysis Result ---");
console.log(`Total Findings: ${findings.length}`);
console.log(JSON.stringify(findings, null, 2));

function determineVerdict(findings) {
    if (findings.some(f => f.severity === "CRITICAL" || f.severity === "HIGH")) return "FAIL";
    if (findings.some(f => f.severity === "MEDIUM")) return "WARN";
    return "PASS";
}

const verdict = determineVerdict(findings);
console.log(`\nVerdict: ${verdict}`);

if (verdict === "FAIL" && findings.length > 0) {
    console.log("\n✅ Test Passed: Detected vulnerabilities and triggered FAIL verdict.");
} else {
    console.log("\n❌ Test Failed: Logic did not trigger expected FAIL verdict.");
}
