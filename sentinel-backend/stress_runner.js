import fs from 'fs';
import path from 'path';
import { StaticAnalyzer } from './staticAnalyzer.js';

/**
 * SentinelPR Stress Test Runner
 * Executes all Tier 1 rules against fixtures and saves JSON results.
 */

const FIXTURES_DIR = 'tests/stress-test/fixtures';
const RESULTS_DIR = 'tests/stress-test/results';

async function runStressTest() {
    console.log('🚀 Starting SentinelPR Stress Test...');
    const analyzer = new StaticAnalyzer();

    if (!fs.existsSync(FIXTURES_DIR)) {
        console.error(`❌ Fixtures directory not found: ${FIXTURES_DIR}`);
        return;
    }

    if (!fs.existsSync(RESULTS_DIR)) {
        fs.mkdirSync(RESULTS_DIR, { recursive: true });
    }

    const files = fs.readdirSync(FIXTURES_DIR).filter(f => f.endsWith('.js') || f.endsWith('.py') || f.endsWith('.xml'));

    for (const file of files) {
        const filePath = path.join(FIXTURES_DIR, file);
        console.log(`🔍 Analyzing: ${file}...`);

        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Generate a fake diff for the entire file content to satisfy the analyzer
            const fakeDiff = `--- a/${file}\n+++ b/${file}\n@@ -1,${content.split('\n').length} +1,${content.split('\n').length} @@\n${content.split('\n').map(line => `+${line}`).join('\n')}`;

            const results = analyzer.analyzeDiff(fakeDiff);

            const resultPath = path.join(RESULTS_DIR, `${file}.results.json`);
            fs.writeFileSync(resultPath, JSON.stringify(results, null, 2));

            console.log(`✅ Results saved to: ${resultPath}`);
            console.log(`📊 Verdict: ${results.verdict}, Findings: ${results.findings.length}`);
        } catch (error) {
            console.error(`❌ Error analyzing ${file}:`, error);
        }
    }

    console.log('\n✨ Stress test complete.');
}

runStressTest();
