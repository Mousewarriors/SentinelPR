import { StaticAnalyzer } from './staticAnalyzer.js';

const analyzer = new StaticAnalyzer();

const diffText = `diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -1,10 +1,15 @@
 const express = require('express');
 const app = express();
-app.use(cors());
+app.use((req, res, next) => {
+  res.header("Access-Control-Allow-Origin", "*");
+  next();
+});
+
+const SESSION_SECRET = "abc1234567890defghijk123456";
+const JWT_SECRET = "too-short";
+
+app.post('/login', (req, res) => {
+  // insecure login without limiter or generic errors
+  if (req.body.user === 'admin') {
+    res.send("User not found");
+  }
+});
+
+app.listen(3000);`;

console.log("🚀 Testing Auth WARN Rules Expansion...");
const result = analyzer.analyzeDiff(diffText);

console.log(`\nVerdict: ${result.verdict}`);
console.log(`Findings Count: ${result.findings.length}`);

result.findings.forEach(f => {
    console.log(`\n[${f.ruleId}] ${f.severity} - ${f.title}`);
    console.log(`Risk: ${f.risk}`);
    console.log(`Snippet: ${f.snippet}`);
});

const triggeredIds = result.findings.map(f => f.ruleId);
const expected = ["W201_PERMISSIVE_CORS", "W206_HARDCODED_SESSION_SECRET", "W209_WEAK_JWT_SECRET", "W211_MISSING_RATE_LIMITING", "W220_VERBOSE_AUTH_ERRORS", "W214_MISSING_CSRF_PROTECTION"];

expected.forEach(id => {
    if (triggeredIds.includes(id)) {
        console.log(`✅ ${id} triggered successfully.`);
    } else {
        console.log(`❌ ${id} failed to trigger.`);
    }
});
