import fs from 'fs';
import path from 'path';
import { StaticAnalyzer } from './staticAnalyzer.js';

/**
 * SentinelPR Benchmark Runner
 * Targets 40 specific real-world benchmark files and reports findings.
 */

const BASE_FIXTURES_DIR = 'scanner-fixtures';
const RESULTS_DIR = 'tests/benchmark-results';

const BENCHMARK_FILES = [
    // Java — OWASP BenchmarkJava (15 files)
    ...Array.from({ length: 15 }, (_, i) => ({
        repo: 'BenchmarkingJava',
        relPath: `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest${String(i + 1).padStart(5, '0')}.java`,
        lang: 'java'
    })),
    // Python — OWASP BenchmarkPython (10 files)
    ...Array.from({ length: 10 }, (_, i) => ({
        repo: 'BenchmarkingPython',
        relPath: `testcode/BenchmarkTest${String(i + 1).padStart(5, '0')}.py`,
        lang: 'python'
    })),
    // C/C++ — Juliet Test Suite (10 files)
    { repo: 'juliet-c', relPath: 'testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_system_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE126_Buffer_Overread/s01/CWE126_Buffer_Overread__char_alloca_memcpy_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE127_Buffer_Underread/s01/CWE127_Buffer_Underread__char_alloca_memcpy_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__char_connect_socket_printf_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE369_Divide_by_Zero/s01/CWE369_Divide_by_Zero__int_fscanf_divide_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE400_Resource_Exhaustion/s01/CWE400_Resource_Exhaustion__fscanf_sleep_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE401_Memory_Leak/s01/CWE401_Memory_Leak__malloc_realloc_int_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE415_Double_Free/s01/CWE415_Double_Free__malloc_free_char_01.c', lang: 'c' },
    { repo: 'juliet-c', relPath: 'testcases/CWE457_Use_of_Uninitialized_Variable/s01/CWE457_Use_of_Uninitialized_Variable__int_01.c', lang: 'c' },
    // JS/TS — OWASP Juice Shop modules (5 files)
    { repo: 'juice-shop', relPath: 'routes/login.ts', lang: 'typescript' },
    { repo: 'juice-shop', relPath: 'routes/search.ts', lang: 'typescript' },
    { repo: 'juice-shop', relPath: 'routes/profileImageUrlUpload.ts', lang: 'typescript' },
    { repo: 'juice-shop', relPath: 'routes/fileServer.ts', lang: 'typescript' },
    { repo: 'juice-shop', relPath: 'routes/showProductReviews.ts', lang: 'typescript' },
];

async function runBenchmark() {
    console.log('🏁 Starting SentinelPR Benchmark (40 Targeted Files)...');
    const analyzer = new StaticAnalyzer();

    if (!fs.existsSync(RESULTS_DIR)) {
        fs.mkdirSync(RESULTS_DIR, { recursive: true });
    }

    let totalFindings = 0;
    let filesAnalyzed = 0;

    for (const entry of BENCHMARK_FILES) {
        const filePath = path.join(BASE_FIXTURES_DIR, entry.repo, entry.relPath);
        const fileName = path.basename(entry.relPath);

        if (!fs.existsSync(filePath)) {
            console.warn(`⚠️ File not found, skipping: ${filePath}`);
            continue;
        }

        console.log(`🔍 [${entry.lang.toUpperCase()}] Analyzing: ${fileName}...`);

        try {
            const content = fs.readFileSync(filePath, 'utf8');

            // Generate a full-file ADDED diff
            const lineCount = content.split('\n').length;
            const fakeDiff = `--- a/${fileName}\n+++ b/${fileName}\n@@ -1,${lineCount} +1,${lineCount} @@\n${content.split('\n').map(l => '+' + l).join('\n')}`;

            const results = analyzer.analyzeDiff(fakeDiff);

            totalFindings += results.findings.length;
            filesAnalyzed++;

            const resultPath = path.join(RESULTS_DIR, `${fileName}.results.json`);
            fs.writeFileSync(resultPath, JSON.stringify({
                meta: entry,
                verdict: results.verdict,
                findingCount: results.findings.length,
                findings: results.findings
            }, null, 2));

        } catch (error) {
            console.error(`❌ Error analyzing ${fileName}:`, error.message);
        }
    }

    console.log(`\n✅ Benchmark Complete!`);
    console.log(`📂 Analyzed: ${filesAnalyzed} / ${BENCHMARK_FILES.length} files`);
    console.log(`📊 Total Findings: ${totalFindings}`);
    console.log(`📝 Results saved in: ${RESULTS_DIR}`);
}

runBenchmark();
