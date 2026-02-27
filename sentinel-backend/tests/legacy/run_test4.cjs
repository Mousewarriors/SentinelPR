const axios = require('axios');
const fs = require('fs');

async function run() {
    console.log("Auditing test4.js (Subtle Suite)...");
    const diff = fs.readFileSync('test4.diff', 'utf8');
    const res = await axios.post('http://localhost:3000/simulate', { diff }, { timeout: 180000 });

    console.log("\n--- [MARCKDOWN SUMMARY] ---");
    console.log(res.data.summaryMarkdown);

    console.log("\n--- [AI FINDINGS] ---");
    if (res.data.tier2.result && res.data.tier2.result.findings) {
        res.data.tier2.result.findings.forEach(f => {
            console.log(`\n[${f.severity}] ${f.title}`);
            console.log(`Explanation: ${f.explanation}`);
        });
    } else {
        console.log("No AI findings or Tier 2 failed.");
    }
}
run().catch(console.error);
