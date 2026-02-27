import axios from 'axios';
import fs from 'fs';
import path from 'path';

const SIMULATE_URL = "http://localhost:3000/simulate";
const GROUND_TRUTH = JSON.parse(fs.readFileSync(path.join('fixtures', 'ground_truth.json'), 'utf8'));

async function evaluateModel(engine = "local") {
    const modelName = process.env.OLLAMA_MODEL || "mistral:latest";
    console.log(`\n=== EVALUATING ENGINE: ${engine} (${modelName}) ===`);
    let passedTests = 0;
    let totalTests = Object.keys(GROUND_TRUTH).length;

    for (const [filename, truth] of Object.entries(GROUND_TRUTH)) {
        console.log(`\n[Test] ${filename}`);
        const diff = fs.readFileSync(path.join('fixtures', filename), 'utf8');

        try {
            const response = await axios.post(SIMULATE_URL, {
                diff: diff,
                tier2_engine: engine
            }, { timeout: 60000 });

            const result = response.data;
            let success = true;

            // Check Conclusion/Verdict
            if (truth.expected_verdict && result.conclusion !== truth.expected_verdict) {
                console.log(`  ❌ Conclusion Mismatch: Expected ${truth.expected_verdict}, got ${result.conclusion}`);
                success = false;
            }

            // Check Tier 2 "Must Find"
            if (engine !== 'off' && truth.must_find_tier2 && result.tier2.status === 'ran') {
                const findingsText = JSON.stringify(result.tier2.result.findings).toLowerCase();
                truth.must_find_tier2.forEach(keyword => {
                    if (!findingsText.includes(keyword.toLowerCase())) {
                        console.log(`  ❌ Tier 2 missed required keyword: "${keyword}"`);
                        success = false;
                    }
                });
            } else if (engine !== 'off' && truth.must_find_tier2 && result.tier2.status !== 'ran') {
                console.log(`  ⚠️ Tier 2 could not run: ${result.tier2.reason || 'unknown'}`);
                success = false;
            }

            if (success) {
                console.log(`  ✅ Passed`);
                passedTests++;
            }
        } catch (error) {
            console.log(`  ❌ Request failed: ${error.message}`);
        }
    }

    console.log(`\nSummary: ${passedTests}/${totalTests} tests passed.`);
}

const targetEngine = process.argv[2] || "local";
evaluateModel(targetEngine);
