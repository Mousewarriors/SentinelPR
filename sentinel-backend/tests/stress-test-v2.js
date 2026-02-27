import fs from 'fs';
import path from 'path';
import { runTier1Analysis } from '../staticAnalyzer.js';

const DIR = './tests/archived-results';

function createFullFileDiff(filePath, content) {
  // Simulate pushing a modified file — every line is an added line
  const lines = content.split('\n');
  let diff = `--- a/${path.basename(filePath)}\n+++ b/${path.basename(filePath)}\n@@ -0,0 +1,${lines.length} @@\n`;
  lines.forEach(line => { diff += `+${line}\n`; });
  return diff;
}

async function runStressTest() {
  const files = ["analyzer1.php", "analyzer1.rb", "analyzer2.py", "analyzer3.js"];
  console.log("=== SENTINELPR STRESS TEST ===\n");
  let totalBlock = 0;

  for (const file of files) {
    const filePath = path.join(DIR, file);
    if (!fs.existsSync(filePath)) { console.warn(`[SKIP] ${file}`); continue; }
    const content = fs.readFileSync(filePath, 'utf-8');
    const diff = createFullFileDiff(filePath, content);
    const findings = runTier1Analysis(diff);
    const blockers = findings.filter(f => ['CRITICAL', 'HIGH'].includes(f.severity));
    totalBlock += blockers.length;
    console.log(`${blockers.length > 0 ? '🔴 FAIL' : '⚪ PASS'}  [${file}] — ${findings.length} total, ${blockers.length} blocking`);
    findings.forEach(f => {
      const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
      console.log(`       ${icon} [${f.severity}] ${f.title} (L${f.location.start_line}): ${(f.evidence?.snippet || '').substring(0, 70).trim()}`);
    });
    console.log();
  }
  console.log(`=== TOTAL BLOCKING: ${totalBlock} ===`);
}

runStressTest().catch(console.error);
