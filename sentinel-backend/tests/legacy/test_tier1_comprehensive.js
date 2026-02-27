import { StaticAnalyzer, UnifiedDiffParser, globalFingerprintStore } from './staticAnalyzer.js';
import assert from 'assert';

const analyzer = new StaticAnalyzer();

async function runTests() {
    console.log("🚀 Starting Tier 1 Rule Verification...\n");

    const testCases = [
        // DOMAIN 1: SECRETS
        {
            ruleId: "S001",
            name: "Private Key",
            should_trigger: "diff --git a/test.key b/test.key\n--- a/test.key\n+++ b/test.key\n@@ -0,0 +1,1 @@\n+-----BEGIN RSA PRIVATE KEY-----",
            should_not_trigger: "diff --git a/test.txt b/test.txt\n--- a/test.txt\n+++ b/test.txt\n@@ -1,1 +1,1 @@\n+This is a public key file maybe?",
            near_miss: "diff --git a/test.txt b/test.txt\n--- a/test.txt\n+++ b/test.txt\n@@ -1,1 +1,1 @@\n+REDACTED PRIVATE KEY"
        },
        {
            ruleId: "S004",
            name: "GitHub Token",
            should_trigger: "diff --git a/config.js b/config.js\n--- a/config.js\n+++ b/config.js\n@@ -1,1 +1,1 @@\n+const token = 'ghp_1234567890abcdef1234567890abcdef1234';",
            should_not_trigger: "diff --git a/config.js b/config.js\n--- a/config.js\n+++ b/config.js\n@@ -1,1 +1,1 @@\n+const token = '';",
            near_miss: "diff --git a/config.js b/config.js\n--- a/config.js\n+++ b/config.js\n@@ -1,1 +1,1 @@\n+const token = 'your_token_here';"
        },
        {
            ruleId: "S007",
            name: "AWS Key Pair",
            should_trigger: "diff --git a/cfg.py b/cfg.py\n--- a/cfg.py\n+++ b/cfg.py\n@@ -1,5 +1,6 @@\n+aws_access_key_id = 'AKIA1234567890ABCDEF'\n+aws_secret_access_key = 'abcd1234efgh5678ijkl9012mnop3456qrst7890'",
            should_not_trigger: "diff --git a/cfg.py b/cfg.py\n--- a/cfg.py\n+++ b/cfg.py\n@@ -1,1 +1,1 @@\n+aws_access_key_id = 'AKIA1234567890ABCDEF'",
            near_miss: "diff --git a/cfg.py b/cfg.py\n--- a/cfg.py\n+++ b/cfg.py\n@@ -1,2 +1,2 @@\n+aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'\n+aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        },

        // DOMAIN 2: EXECUTION
        {
            ruleId: "E001",
            name: "eval()",
            should_trigger: "diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1,1 +1,1 @@\n+eval(data);",
            should_not_trigger: "diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1,1 +1,1 @@\n+console.log('eval is bad');"
        },
        {
            ruleId: "E004",
            name: "Python shell=True",
            should_trigger: "diff --git a/ops.py b/ops.py\n--- a/ops.py\n+++ b/ops.py\n@@ -1,1 +1,1 @@\n+subprocess.run('ls', shell=True)",
            should_not_trigger: "diff --git a/ops.py b/ops.py\n--- a/ops.py\n+++ b/ops.py\n@@ -1,1 +1,1 @@\n+subprocess.run(['ls'])"
        },

        // DOMAIN 3: TLS
        {
            ruleId: "T001",
            name: "TLS Disable",
            should_trigger: "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1,1 +1,1 @@\n+NODE_TLS_REJECT_UNAUTHORIZED=0",
            should_not_trigger: "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1,1 +1,1 @@\n+NODE_TLS_REJECT_UNAUTHORIZED=1"
        },

        // DOMAIN 7: CI
        {
            ruleId: "C002",
            name: "Unpinned Action",
            should_trigger: "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -10,1 +10,1 @@\n+      - uses: actions/checkout@v3",
            should_not_trigger: "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -10,1 +10,1 @@\n+      - uses: actions/checkout@ac593985615ec2ede58e132d2e21d2b1cbd6127c"
        }
    ];

    let passed = 0;
    let failed = 0;

    for (const tc of testCases) {
        process.stdout.write(`Testing ${tc.ruleId} (${tc.name})... `);
        try {
            // Test trigger
            const triggerResult = analyzer.analyzeDiff(tc.should_trigger);
            assert(triggerResult.findings.some(f => f.ruleId === tc.ruleId), `Should have triggered ${tc.ruleId}`);

            // Test non-trigger
            const nonTriggerResult = analyzer.analyzeDiff(tc.should_not_trigger);
            assert(!nonTriggerResult.findings.some(f => f.ruleId === tc.ruleId), `Should NOT have triggered ${tc.ruleId}`);

            // Test near miss
            if (tc.near_miss) {
                const nearMissResult = analyzer.analyzeDiff(tc.near_miss);
                assert(!nearMissResult.findings.some(f => f.ruleId === tc.ruleId), `Near miss should NOT have triggered ${tc.ruleId}`);
            }

            console.log("✅");
            passed++;
        } catch (err) {
            console.log("❌");
            console.error(`  Error: ${err.message}`);
            failed++;
        }
    }

    console.log(`\nResults: ${passed} passed, ${failed} failed.`);

    // --- BASELINE TEST ---
    console.log("\nTesting Baseline Scan & Fingerprinting...");
    const baselineFiles = [
        { path: 'old_secrets.txt', content: 'GITHUB_TOKEN=ghp_oldtoken1234567890abcdef1234567890ghp_longer_now' }
    ];
    analyzer.setContext('test-repo', 'init-sha');
    const baselineFindings = analyzer.analyzeBaseline(baselineFiles);
    console.log(`- Baseline found ${baselineFindings.length} secrets.`);

    const newPrDiff = `diff --git a/new.js b/new.js\n--- a/new.js\n+++ b/new.js\n@@ -1,2 +1,2 @@\n+const t1 = "ghp_oldtoken1234567890abcdef1234567890ghp_longer_now";\n+const t2 = "ghp_newtoken9876543210fedcba0987654321ghp_longer_now";`;
    const prResult = analyzer.analyzeDiff(newPrDiff);

    const preExisting = prResult.findings.find(f => f.status === "PRE-EXISTING");
    const newSecret = prResult.findings.find(f => f.status === "NEW");

    assert(preExisting, "Should have found pre-existing secret");
    assert(newSecret, "Should have found new secret");
    console.log("✅ Baseline fingerprinting works: identified New vs Pre-existing.");

    if (failed > 0) process.exit(1);
}

runTests().catch(err => {
    console.error(err);
    process.exit(1);
});
