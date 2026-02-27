import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { App } from "octokit";
import fs from "fs";
import yaml from "js-yaml";
import { runTier1Analysis } from "./staticAnalyzer.js";
import { runTier2Analysis } from "./tier2Analyzer.js";
import { checkUsage, incrementUsage } from "./usageTracker.js";

const DEDUPE_FILE = process.env.DEDUPE_FILE || ".dedupe.json";
let commentedKeys = [];
try {
    if (fs.existsSync(DEDUPE_FILE)) {
        commentedKeys = JSON.parse(fs.readFileSync(DEDUPE_FILE, "utf8"));
    }
} catch (err) { }

const commented = new Set(commentedKeys);

function saveDedupe() {
    try {
        const keys = Array.from(commented).slice(-5000);
        fs.writeFileSync(DEDUPE_FILE, JSON.stringify(keys, null, 2), "utf8");
    } catch (err) { }
}

// --- In-flight check run registry for graceful shutdown ---
// Tracks active GitHub check runs so we can close them cleanly on restart
const inFlightChecks = new Map(); // key -> { octokit, owner, repo, checkRunId }

function registerCheck(key, octokit, owner, repo, checkRunId) {
    inFlightChecks.set(key, { octokit, owner, repo, checkRunId });
}

function unregisterCheck(key) {
    inFlightChecks.delete(key);
}

async function cancelAllInFlightChecks(reason = "Server restarted") {
    if (inFlightChecks.size === 0) return;
    console.log(`[Shutdown] Cancelling ${inFlightChecks.size} in-flight check run(s)...`);
    const promises = [];
    for (const [key, { octokit, owner, repo, checkRunId }] of inFlightChecks) {
        promises.push(
            octokit.rest.checks.update({
                owner, repo, check_run_id: checkRunId,
                status: "completed",
                conclusion: "action_required",
                completed_at: new Date().toISOString(),
                output: {
                    title: "Scan Interrupted",
                    summary: `⚠️ SentinelPR was restarted during this scan. Please push a new commit or re-open the PR to trigger a fresh scan.`
                }
            }).catch(e => console.error(`[Shutdown] Failed to cancel check ${key}:`, e.message))
        );
    }
    await Promise.allSettled(promises);
    inFlightChecks.clear();
}

async function gracefulShutdown(signal) {
    console.log(`[Shutdown] Received ${signal} — cleaning up...`);
    await cancelAllInFlightChecks(signal);
    saveDedupe();
    process.exit(0);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("uncaughtException", async (err) => {
    console.error("[Uncaught Exception]", err);
    await cancelAllInFlightChecks("crash");
    process.exit(1);
});

const app = express();
const port = process.env.PORT || 3000;

let privateKey = process.env.GITHUB_PRIVATE_KEY;
if (!privateKey && process.env.GITHUB_APP_PRIVATE_KEY_PATH) {
    try {
        privateKey = fs.readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, "utf8");
    } catch (err) { }
}

const githubApp = new App({
    appId: process.env.GITHUB_APP_ID,
    privateKey,
});

app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

function verifySignature(req) {
    const signature = req.headers["x-hub-signature-256"];
    const secret = process.env.GITHUB_WEBHOOK_SECRET;
    if (!signature || !secret) return false;
    const hmac = crypto.createHmac("sha256", secret);
    const digest = "sha256=" + hmac.update(req.rawBody).digest("hex");
    try {
        return crypto.timingSafeEqual(Buffer.from(signature, "utf8"), Buffer.from(digest, "utf8"));
    } catch { return false; }
}

function mapSeverityEmoji(sev) {
    switch (sev?.toUpperCase()) {
        case "CRITICAL": return "🔴";
        case "HIGH": return "🟠";
        case "MEDIUM": return "🟡";
        case "LOW": return "🔵";
        default: return "⚪";
    }
}

function generateMarkdownSummary(context, result, usage) {
    const { owner, repo, prNumber, headSha } = context;
    const { conclusion, tier1, tier2 } = result;
    const modelName = process.env.OLLAMA_MODEL || "local-llm";
    const shortSha = headSha.substring(0, 7);

    const t1Blocking = tier1.filter(f => ["CRITICAL", "HIGH"].includes(f.severity));
    const t1Warning = tier1.filter(f => f.severity === "MEDIUM");
    const t2Findings = tier2.result?.findings || [];

    let verdictStatus = "PASS";
    let verdictHeader = "## ✅ **PASS — No blocking security issues detected**";
    if (conclusion === "failure") {
        verdictStatus = "FAIL";
        verdictHeader = "## ❌ **FAIL — Security issues must be fixed before merge**";
    } else if (conclusion === "neutral") {
        verdictStatus = "WARN";
        verdictHeader = "## ⚠️ **WARN — Security review passed with concerns**";
    }

    let t2StatusText = "✅ Ran";
    if (tier2.status === "unavailable") t2StatusText = `❌ AI unavailable (${tier2.reason})`;
    else if (tier2.status === "ignored") t2StatusText = `❌ AI ignored (${tier2.reason})`;
    else if (tier2.status === "limit_reached") t2StatusText = `❌ AI limit reached`;

    const summarySentence = conclusion === "failure"
        ? "Security issues identified that require attention."
        : "No critical security issues identified.";

    const hasT2Blocking = t2Findings.some(f => f.severity === "CRITICAL" && f.confidence === "HIGH");


    const allFindings = [
        ...tier1.map(f => ({ ...f, sourceTier: 1 })),
        ...t2Findings.map(f => ({ ...f, sourceTier: 2 }))
    ];

    // Group by severity
    const severityMap = { "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": [] };
    allFindings.forEach(f => {
        const sev = f.severity?.toUpperCase() || "INFO";
        if (severityMap[sev]) severityMap[sev].push(f);
        else severityMap["INFO"].push(f);
    });

    const getSeverityIcon = (sev) => {
        switch (sev) {
            case "CRITICAL": return "🔴";
            case "HIGH": return "🟠";
            case "MEDIUM": return "🟡";
            case "LOW": return "🔵";
            default: return "⚪";
        }
    };

    const renderSeverityRow = (sev, label) => {
        const count = severityMap[sev].length;
        const status = count > 0 ? (sev === "CRITICAL" || sev === "HIGH" ? "🚨 Attention Required" : "⚠️ Review Suggested") : "✅ Clear";
        return `| ${getSeverityIcon(sev)} **${label}** | ${count} | ${status} |`;
    };

    const renderFindingTable = (f, sourceTier) => {
        const isTier1 = sourceTier === 1;
        const filePath = isTier1 ? f.location.path : f.evidence.file;
        const lineNum = isTier1 ? f.location.start_line : f.evidence.line;
        const snippet = isTier1 ? f.evidence?.snippet : (f.evidence?.code_snippet || f.evidence?.snippet);

        let impact = isTier1 ? f.description : f.explanation;
        let fix = isTier1 ? f.recommended_fix : f.recommendation;

        const cleanStr = (s) => (s || "").replace(/^(Impact|Fix|Recommendation|Explanation|Risk|Description|Mitigation):\s*/i, "").trim();
        impact = cleanStr(impact);
        fix = cleanStr(fix);

        // Wider wrapping (approx 100 characters)
        const wrapText = (text, limit = 100) => {
            if (!text) return "";
            const words = text.split(" ");
            let currentLine = "";
            const lines = [];
            words.forEach(word => {
                if ((currentLine + word).length > limit) {
                    lines.push(currentLine.trim());
                    currentLine = word + " ";
                } else {
                    currentLine += word + " ";
                }
            });
            if (currentLine) lines.push(currentLine.trim());
            return lines.join("<br/>");
        };

        const severityEmoji = getSeverityIcon(f.severity?.toUpperCase());

        const formatSnippet = (s) => {
            if (!s) return "";
            const escaped = s.trim().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            return `<code>${escaped.replace(/\n/g, "<br/>")}</code>`;
        };

        const snippetRow = snippet ? `| **Vulnerable Line:** ${formatSnippet(snippet)} |` : "";

        // Enforce 100 character width
        const heading = `${severityEmoji} **${f.title}**`;
        const spacer = "&nbsp;".repeat(Math.max(0, 100 - heading.replace(/\*\*/g, "").length));

        return `| ${heading}${spacer} |
| :--- |
| **Location:** \`${filePath}:${lineNum}\` |
${snippetRow}
| **Impact:** ${wrapText(impact)} |
| **Recommendation:** ${wrapText(fix)} |
`;
    };

    const renderSeverityGroup = (label, sevKey) => {
        const findings = severityMap[sevKey];
        if (findings.length === 0) return "";
        return `### ${label}\n${findings.map(f => renderFindingTable(f, f.sourceTier)).join("\n")}\n---`;
    };

    return `
# 🔐 SentinelPR — Security Review

${verdictHeader}

**Repository:** ${owner}/${repo} | **PR:** #${prNumber} | **Commit:** \`${shortSha}\`
**Plan:** ${usage.tier} (${usage.current}/${usage.limit} PRs)

---

## 📊 Security Posture Summary

| Severity | Findings | Status |
| :--- | :--- | :--- |
${renderSeverityRow("CRITICAL", "Critical")}
${renderSeverityRow("HIGH", "High")}
${renderSeverityRow("MEDIUM", "Medium")}
${renderSeverityRow("LOW", "Low")}

---

## 🚨 Security issues identified that require attention

${allFindings.length === 0 ? "> No security issues identified." : `
${renderSeverityGroup("🔴 Critical Priority", "CRITICAL")}
${renderSeverityGroup("🟠 High Priority", "HIGH")}
${renderSeverityGroup("🟡 Medium Priority", "MEDIUM")}
${renderSeverityGroup("🔵 Low Priority", "LOW")}
${renderSeverityGroup("⚪ Info / Advisory", "INFO")}
`.trim()}

---

## 🧪 What SentinelPR Did

* **Pattern Analysis**: Scanned code for known security vulnerabilities and anti-patterns.
* **Semantic Review**: Performed a Triple-Pass audit for logic, infrastructure, and configuration risks.
* **Fair Validation**: Verified high-confidence findings to minimize noise.

---

## ✅ Final Verdict

**${verdictStatus}**

${conclusion === "failure" ? "Please address the priority issues above before merging." : "Security review complete."}

---

### ℹ️ Need Help?
Verify findings in **Files changed**. SentinelPR aims for high precision and fair reporting.
`.trim();
}

function mapSeverityToAnnotationLevel(severity) {
    switch (severity) {
        case "CRITICAL":
        case "HIGH": return "failure";
        case "MEDIUM": return "warning";
        default: return "notice";
    }
}

async function processAnalysis(owner, repo, prNumber, headSha, diff) {
    const tier1 = runTier1Analysis(diff);
    const tier2Results = await runTier2Analysis(owner, repo, prNumber, headSha, diff, tier1.length > 0 ? `${tier1.length} static issues.` : "None.");

    const annotations = [
        ...tier1.map(f => ({
            path: f.location?.path || "unknown",
            start_line: f.location?.start_line || 1,
            end_line: f.location?.end_line || 1,
            annotation_level: mapSeverityToAnnotationLevel(f.severity),
            title: `[Static] ${f.title}`,
            message: `${f.description}\nFix: ${f.recommended_fix}`
        })),
        ...(tier2Results.result?.findings || []).map(f => ({
            path: f.evidence?.file || "unknown",
            start_line: f.evidence?.line || 1,
            end_line: f.evidence?.line || 1,
            annotation_level: "notice",
            title: `[AI] ${f.title}`,
            message: `${f.explanation}\nRec: ${f.recommendation}`
        }))
    ];

    const t2Findings = tier2Results.result?.findings || [];
    const hasT1Failure = tier1.some(f => ["CRITICAL", "HIGH"].includes(f.severity));
    const hasT2CriticalHighConfidence = t2Findings.some(f => f.severity === "CRITICAL" && f.confidence === "HIGH");

    const conclusion = (hasT1Failure || hasT2CriticalHighConfidence) ? "failure" : (tier1.some(f => f.severity === "MEDIUM") ? "neutral" : "success");

    return { conclusion, annotations, tier1, tier2: tier2Results };
}

app.post("/github/webhook", async (req, res) => {
    console.log(`[Webhook] Received ${req.headers["x-github-event"]} event from GitHub`);
    res.status(200).send("Accepted");

    if (!verifySignature(req)) {
        console.warn("[Webhook] Signature verification failed!");
        return;
    }

    if (req.headers["x-github-event"] === "pull_request") {
        const { action, pull_request, repository, installation } = req.body;
        if (!["opened", "reopened", "synchronize"].includes(action)) return;

        const owner = repository.owner.login;
        const repo = repository.name;
        const prNumber = pull_request.number;
        const headSha = pull_request.head.sha;

        const key = `${repository.full_name}#${prNumber}@${headSha}`;
        if (commented.has(key)) return;

        try {
            const octokit = await githubApp.getInstallationOctokit(installation.id);

            const checkRun = await octokit.rest.checks.create({
                owner, repo, name: "SentinelPR", head_sha: headSha,
                status: "in_progress", started_at: new Date().toISOString()
            });

            // Track this check run so we can cancel it cleanly on server shutdown
            registerCheck(key, octokit, owner, repo, checkRun.data.id);

            const { data: diff } = await octokit.rest.pulls.get({
                owner, repo, pull_number: prNumber, mediaType: { format: "diff" }
            });

            // --- DIAGNOSTIC: Log diff summary and dump to file ---
            const diffLines = (diff || "").split("\n");
            const addedCount = diffLines.filter(l => l.startsWith("+") && !l.startsWith("+++")).length;
            const contextCount = diffLines.filter(l => l.startsWith(" ")).length;
            console.log(`[Diff] Total lines: ${diffLines.length} | Added: ${addedCount} | Context: ${contextCount}`);
            console.log(`[Diff] Files changed: ${[...diffLines.filter(l => l.startsWith("+++ b/")).map(l => l.substring(6))].join(", ")}`);
            console.log(`[Diff] Preview:\n${(diff || "(empty)").substring(0, 800)}`);
            // Write full diff to disk for inspection
            import('fs').then(fsMod => fsMod.default.writeFileSync(`./tests/last_github_diff.txt`, diff || "", 'utf8'));

            // --- Usage Gating ---
            const usage = checkUsage(installation.id);
            let result;

            if (usage.allowed) {
                result = await processAnalysis(owner, repo, prNumber, headSha, diff);
                incrementUsage(installation.id);
            } else {
                console.log(`[Usage] Limit reached for installation ${installation.id} (${usage.tier})`);
                const tier1 = runTier1Analysis(diff);
                result = {
                    conclusion: tier1.some(f => ["CRITICAL", "HIGH"].includes(f.severity)) ? "failure" : "success",
                    tier1,
                    tier2: { status: "limit_reached", reason: `Monthly quota for ${usage.tier} plan exceeded.` },
                    annotations: tier1.map(f => ({
                        path: f.location.path,
                        start_line: f.location.start_line,
                        end_line: f.location.end_line,
                        annotation_level: mapSeverityToAnnotationLevel(f.severity),
                        title: `[Static] ${f.title}`,
                        message: `${f.description}\nFix: ${f.recommended_fix}`
                    }))
                };
            }

            await octokit.rest.checks.update({
                owner, repo, check_run_id: checkRun.data.id,
                status: "completed", conclusion: result.conclusion,
                output: {
                    title: `Security Scan Results`,
                    summary: generateMarkdownSummary({ owner, repo, prNumber, headSha }, result, usage),
                    annotations: [] // Cleared as requested to remove redundant bottom section
                }
            });

            commented.add(key);
            unregisterCheck(key);
            saveDedupe();
        } catch (err) {
            console.error(err);
            unregisterCheck(key); // ensure we clean up even on error
        }
    }
});

app.post("/simulate", async (req, res) => {
    const { diff } = req.body;
    try {
        const usage = { tier: "SIMULATION", current: 0, limit: 999 };
        const result = await processAnalysis("test", "test", 1, "sha-" + Date.now(), diff);
        res.json({
            ...result,
            summaryMarkdown: generateMarkdownSummary({ owner: "test", repo: "test", prNumber: 1, headSha: "sha-test" }, result, usage)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/", (req, res) => res.send("Running"));
app.listen(port, "0.0.0.0", () => {
    console.log(`Serving on ${port}`);
    // Keep-alive for environments that might prematurely exit
    setInterval(() => {
        if (process.env.DEBUG_HEARTBEAT) console.log("[Heartbeat] Server is alive...");
    }, 60000);
});
