// test_local_server.js

const diff = `--- a/app.js
+++ b/app.js
@@ -1,5 +1,10 @@
-console.log("Hello world");
+const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";
+const apiKey = "AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
+
+const axios = require('axios');
+const client = axios.create({ rejectUnauthorized: false });
+
+console.log("Debug token:", token);
`;

async function testSimulate() {
    console.log("Sending simulation request to server...");
    try {
        const response = await fetch("http://localhost:3000/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ diff })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server error (${response.status}): ${errorText}`);
        }

        const result = await response.json();
        console.log("\n--- Simulation Result ---");
        console.log("Conclusion:", result.conclusion);
        console.log("Tier 1 Findings:", result.tier1.length);
        console.log("Tier 2 Status:", result.tier2.status);

        console.log("\n--- Summary Markdown ---");
        console.log(result.summaryMarkdown);

        console.log("\n--- Annotations ---");
        result.annotations.forEach(a => {
            console.log(`[${a.annotation_level}] ${a.title} @ ${a.path}:${a.start_line}`);
        });

    } catch (err) {
        console.error("Test failed:", err.message);
    }
}

testSimulate();
