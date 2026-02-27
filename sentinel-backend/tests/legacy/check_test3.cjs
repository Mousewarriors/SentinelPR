const axios = require('axios');
const fs = require('fs');
const path = require('path');

async function testV20() {
    console.log("Reading test3.js...");
    const content = fs.readFileSync('test3.js', 'utf8');

    // Create a mock unified diff for the whole file
    const diff = `--- /dev/null\n+++ b/test3.js\n@@ -0,0 +1,${content.split('\n').length} @@\n` + content.split('\n').map(l => '+' + l).join('\n');

    console.log("Sending to /simulate (this may take up to 90s)...");
    try {
        const res = await axios.post('http://localhost:3000/simulate', { diff }, { timeout: 300000 });
        console.log("\n--- [Analysis Results] ---");
        console.log(`Conclusion: ${res.data.conclusion}`);
        console.log(`T1 Findings: ${res.data.tier1.length}`);
        console.log(`T2 Status: ${res.data.tier2.status}`);

        if (res.data.tier2.result && res.data.tier2.result.findings) {
            console.log(`T2 Findings: ${res.data.tier2.result.findings.length}`);
            res.data.tier2.result.findings.forEach(f => {
                console.log(` - [${f.severity}] ${f.title}: ${f.explanation.slice(0, 100)}...`);
            });
        } else if (res.data.tier2.status === 'unavailable') {
            console.error(`❌ Tier 2 Failed: ${res.data.tier2.reason}`);
        }
    } catch (err) {
        console.error(`❌ Request failed: ${err.message}`);
    }
}

testV20();
