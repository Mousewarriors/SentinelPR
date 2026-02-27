import { GoogleGenerativeAI } from "@google/generative-ai";
import fs from "fs";
import path from "path";

/**
 * Tier 2 Analysis using LLM (Gemini or Ollama)
 */
export async function runTier2Analysis(owner, repo, prNumber, headSha, diffText, tier1Summary) {
    const engine = process.env.TIER2_ENGINE || "cloud";

    if (engine === "local") {
        return await runOllamaAnalysis(owner, repo, prNumber, headSha, diffText, tier1Summary);
    } else {
        return await runGeminiAnalysis(owner, repo, prNumber, headSha, diffText, tier1Summary);
    }
}

async function runGeminiAnalysis(owner, repo, prNumber, headSha, diffText, tier1Summary) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === "your_key_here") {
        return { status: "unavailable", reason: "GEMINI_API_KEY missing" };
    }

    try {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });
        const { systemPrompt, userPrompt } = preparePrompts(owner, repo, prNumber, headSha, diffText, tier1Summary);

        const result = await model.generateContent({
            contents: [{ role: "user", parts: [{ text: `${systemPrompt}\n\n${userPrompt}` }] }],
            generationConfig: { responseMimeType: "application/json" }
        });

        return { status: "success", result: JSON.parse(result.response.text()) };
    } catch (error) {
        console.error(`[Tier 2] Gemini failed: ${error.message}`);
        return { status: "unavailable", reason: error.message };
    }
}

async function runOllamaAnalysis(owner, repo, prNumber, headSha, diffText, tier1Summary) {
    const url = process.env.OLLAMA_URL || "http://localhost:11434";
    const model = process.env.OLLAMA_MODEL || "qwen2.5:14b";

    try {
        const { systemPrompt, userPrompt } = preparePrompts(owner, repo, prNumber, headSha, diffText, tier1Summary);

        const response = await fetch(`${url}/api/generate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                model: model,
                prompt: `${systemPrompt}\n\n${userPrompt}`,
                format: "json",
                stream: false,
                options: { num_ctx: 32000, temperature: 0.1 }
            })
        });

        if (!response.ok) throw new Error(`Ollama error: ${response.statusText}`);

        const data = await response.json();
        return { status: "success", result: JSON.parse(data.response) };
    } catch (error) {
        console.error(`[Tier 2] Ollama failed: ${error.message}`);
        return { status: "unavailable", reason: error.message };
    }
}

function preparePrompts(owner, repo, prNumber, headSha, diffText, tier1Summary) {
    const directivePath = path.join(process.cwd(), "..", "directives");
    const securityPolicy = fs.readFileSync(path.join(directivePath, "sentinel_security_policy.md"), "utf8");
    const outputSchema = fs.readFileSync(path.join(directivePath, "sentinel_output_schema.md"), "utf8");
    const severityGating = fs.readFileSync(path.join(directivePath, "sentinel_severity_gating.md"), "utf8");
    const prTask = fs.readFileSync(path.join(directivePath, "sentinel_pr_task.md"), "utf8");

    const systemPrompt = `${securityPolicy}\n\n${outputSchema}\n\n${severityGating}`.trim();
    const userPrompt = `
${prTask}

Repository: ${owner}/${repo}
PR Number: ${prNumber}
Head SHA: ${headSha}
Static Analysis Summary: ${tier1Summary}

Unified Diff:
\`\`\`diff
${diffText}
\`\`\`
    `.trim();

    return { systemPrompt, userPrompt };
}
