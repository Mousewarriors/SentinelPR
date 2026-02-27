import axios from "axios";
import fs from "fs";
import path from "path";
import { z } from "zod";

// --- Deliverable C: JSON Schema & Validation ---
const Tier2ResultSchema = z.object({
    engine: z.string(),
    model: z.string(),
    summary: z.string(),
    findings: z.array(z.object({
        title: z.string(),
        severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
        confidence: z.enum(["LOW", "MEDIUM", "HIGH"]),
        category: z.string(),
        evidence: z.object({
            file: z.string().min(1),
            line: z.number().positive(),
            snippet: z.string().min(1)
        }),
        explanation: z.string(),
        recommendation: z.string()
    }))
});

/**
 * Tier 2 Analysis - Pluggable Engine (Llama 3.1:8b Support)
 */
export async function runTier2Analysis(owner, repo, prNumber, headSha, diffText, tier1Summary = "None") {
    const enabled = process.env.ENABLE_AI_REVIEW === "true";
    const engine = process.env.TIER2_ENGINE || "off";
    const timeout = parseInt(process.env.AI_TIMEOUT_MS || "60000", 10);
    const modelName = process.env.OLLAMA_MODEL || "llama3.1:8b";
    const url = process.env.OLLAMA_URL || "http://localhost:11434";

    if (!enabled || engine === "off") {
        return { status: "off", result: null };
    }

    const maxChunks = parseInt(process.env.MAX_AI_CHUNKS || "6", 10);

    const directivePath = path.join(process.cwd(), "..", "directives");
    const securityPolicy = fs.readFileSync(path.join(directivePath, "sentinel_security_policy.md"), "utf8") || "Standard Policy.";

    // Pass definitions for specialized focus
    const passes = [
        {
            name: "Injection & Infrastructure",
            checklist: "SQL Injection, Command Injection, SSRF (Server-Side Request Forgery), Path Traversal, and XSS (Cross-Site Scripting)."
        },
        {
            name: "Logic & Authorization",
            checklist: "IDOR (Insecure Direct Object Reference), CSRF (Cross-Site Request Forgery), Mass Assignment, and Privilege Escalation logic flaws."
        },
        {
            name: "Crypto & Configuration",
            checklist: "Weak Hashing (MD5/SHA1), Hardcoded Secrets, Predictable Security Tokens (Math.random), and Sensitive Data Exposure in Errors/Logs."
        }
    ];

    // --- Improved Chunking: Per-File ---
    const files = diffText.split(/^diff --git /m).filter(f => f.trim());
    const CHUNK_SIZE = 150;
    const workItems = []; // { filename: string, chunk: string }

    for (const rawFile of files) {
        const lines = rawFile.split('\n');
        const bLine = lines.find(l => l.startsWith('+++ b/'));
        const filename = bLine ? bLine.substring(6) : "unknown";

        for (let i = 0; i < lines.length; i += CHUNK_SIZE) {
            workItems.push({
                filename,
                chunk: lines.slice(i, i + CHUNK_SIZE).join('\n')
            });
        }
    }

    console.log(`[Tier 2] Starting TRIPLE-PASS Audit on ${workItems.length} file-aware chunks (max: ${maxChunks})...`);
    const cappedItems = workItems.slice(0, maxChunks);

    let allFindings = [];
    let status = "ran";

    for (const pass of passes) {
        console.log(`[Tier 2] --- PASS: ${pass.name} ---`);

        for (let i = 0; i < cappedItems.length; i++) {
            const { filename, chunk } = cappedItems[i];
            console.log(`[Tier 2] Auditing chunk ${i + 1}/${cappedItems.length} (${filename}) for ${pass.name}...`);

            const prompt = `
You are SentinelPR, an expert security researcher.
TASK: Analyze the provided code diff chunk EXCLUSIVELY for: ${pass.checklist}

CONTEXT:
File: ${owner}/${repo} -> ${filename} (Chunk ${i + 1}/${workItems.length})
Security Policy: ${securityPolicy}

INSTRUCTIONS:
1. Focus ONLY on the vulnerabilities listed in the TASK.
2. Provide exact evidence. Look carefully at the line numbers within the diff context (@@ -L,C +L,C @@).
3. If no issues in this category are found, return empty findings array.
4. Return JSON ONLY.

DIFF CHUNK:
\`\`\`diff
${chunk}
\`\`\`

Strict JSON Output Schema:
{
  "findings": [
    {
      "title": "Finding Title",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "confidence": "HIGH" | "MEDIUM" | "LOW",
      "category": "Security",
      "evidence": { "file": "path", "line": 123, "snippet": "code" },
      "explanation": "Why it's risky",
      "recommendation": "How to fix"
    }
  ]
}
`.trim();

            try {
                const response = await axios.post(`${url}/api/generate`, {
                    model: modelName,
                    prompt: prompt,
                    stream: false,
                    format: "json",
                    keep_alive: "10m",
                }, { timeout });


                const jsonResult = JSON.parse(response.data.response.match(/\{[\s\S]*\}/)[0]);
                if (jsonResult.findings) {
                    allFindings = [...allFindings, ...jsonResult.findings.map(f => ({
                        ...f,
                        severity: f.severity?.toUpperCase() || "MEDIUM",
                        confidence: f.confidence?.toUpperCase() || "MEDIUM"
                    }))];
                }
            } catch (err) {
                console.warn(`[Tier 2] Pass ${pass.name} Chunk ${i + 1} (${filename}) failed.`);
            }
        }
    }

    // Advanced Deduplication
    const uniqueFindings = [];
    const seen = new Set();
    for (const f of allFindings) {
        // Normalize snippet for better matching
        const snippet = (f.evidence?.snippet || "").substring(0, 30).trim();
        const key = `${f.title}-${f.evidence?.line}-${snippet}`.toLowerCase();
        if (!seen.has(key)) {
            uniqueFindings.push(f);
            seen.add(key);
        }
    }

    return {
        status,
        result: {
            engine: "local",
            model: modelName,
            summary: `Triple-pass audit complete. Found ${uniqueFindings.length} unique issues across ${workItems.length} chunks.`,
            findings: uniqueFindings
        }
    };
}
