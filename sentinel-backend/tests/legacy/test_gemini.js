import "dotenv/config";
import { runTier2Analysis } from "./llmAnalyzer.js";

const sampleDiff = `
diff --git a/auth.js b/auth.js
index e69de29..e123456 100644
--- a/auth.js
+++ b/auth.js
@@ -10,3 +10,6 @@
+function checkAccess(user) {
+  // Subtle logic flaw: anyone with a 'test' email gets admin
+  if (user.email.includes('test')) return 'admin'; 
+  return user.role;
+}
`;

async function main() {
    console.log("🚀 Starting Gemini 2.0 Flash Tier 2 Test...");

    if (process.env.GEMINI_API_KEY === "your_gemini_api_key_here" || !process.env.GEMINI_API_KEY) {
        console.error("❌ Error: GEMINI_API_KEY is not set in .env");
        return;
    }

    try {
        const result = await runTier2Analysis(
            "test-owner/test-repo",
            42,
            "sha-12345",
            sampleDiff
        );

        console.log("\n--- [Gemini Flash Response] ---");
        console.log(JSON.stringify(result, null, 2));

        if (result.findings && result.findings.length > 0) {
            console.log("\n✅ Success! Gemini detected the logic flaw.");
        } else {
            console.log("\n⚠️ Gemini did not find any issues in this diff.");
        }
    } catch (err) {
        console.error("\n❌ Analysis failed:", err.message);
    }
}

main();
