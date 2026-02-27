import { FAIL_INJECTION_RULES } from '../src/tier1/rules/fail/injection.js';
import { PATH002_PYTHON_USER_INPUT_OPEN } from '../src/tier1/rules/fail/files.js';

// Mock version of generateMarkdownSummary logic for verification
const mapSeverityEmoji = (sev) => {
    switch (sev?.toUpperCase()) {
        case "CRITICAL": return "🔴";
        case "HIGH": return "🟠";
        case "MEDIUM": return "🟡";
        case "LOW": return "🔵";
        default: return "⚪";
    }
};

const getSeverityIcon = (sev) => {
    switch (sev) {
        case "CRITICAL": return "🔴";
        case "HIGH": return "🟠";
        case "MEDIUM": return "🟡";
        case "LOW": return "🔵";
        default: return "⚪";
    }
};

const renderSeverityRow = (sev, label, severityMap) => {
    const count = severityMap[sev].length;
    const status = count > 0 ? (sev === "CRITICAL" || sev === "HIGH" ? "🚨 Attention Required" : "⚠️ Review Suggested") : "✅ Clear";
    return `| ${getSeverityIcon(sev)} **${label}** | ${count} | ${status} |`;
};

const renderFindingTable = (f, sourceTier) => {
    const isTier1 = sourceTier === 1;
    const filePath = isTier1 ? f.location?.path : f.evidence?.file;
    const lineNum = isTier1 ? f.location?.start_line : f.evidence?.line;
    const snippet = isTier1 ? f.evidence?.snippet : (f.evidence?.code_snippet || f.evidence?.snippet);

    let impact = isTier1 ? f.description : f.explanation;
    let fix = isTier1 ? f.recommended_fix : f.recommendation;

    const cleanStr = (s) => (s || "").replace(/^(Impact|Fix|Recommendation|Explanation|Risk|Description|Mitigation):\s*/i, "").trim();
    impact = cleanStr(impact);
    fix = cleanStr(fix);

    const confidenceStr = (!isTier1 && f.confidence) ? ` (Confidence: ${f.confidence})` : "";
    const snippetRow = snippet ? `\n| **Vulnerable Line** | \`\`\`\n${snippet.trim()}\n\`\`\` |` : "";

    return `
| **Security Issue** | **${f.title}${confidenceStr}** |
| :--- | :--- |
| **Location** | \`${filePath}:${lineNum}\` |${snippetRow}
| **Impact** | ${impact} |
| **Recommendation** | ${fix} |
`;
};

const renderSeverityGroup = (label, sevKey, severityMap) => {
    const findings = severityMap[sevKey];
    if (findings.length === 0) return "";
    return `### ${label}\n${findings.map(f => renderFindingTable(f, f.sourceTier)).join("\n")}\n---`;
};

function generateMockSummary() {
    const tier1 = [
        { ...FAIL_INJECTION_RULES.find(r => r.id === "SQL002_CONCAT_TO_QUERY"), location: { path: "analysis.py", start_line: 10 }, evidence: { snippet: "db.execute('SELECT * FROM users WHERE id = ' + input)" } },
        { ...PATH002_PYTHON_USER_INPUT_OPEN, location: { path: "analysis.py", start_line: 15 }, evidence: { snippet: "open(path, 'r')" } }
    ].map(f => ({ ...f, sourceTier: 1 }));

    const t2Findings = [
        { severity: "LOW", title: "Weak Hashing", explanation: "Impact: No modern hashing detected.", recommendation: "Fix: Add bcrypt.", evidence: { file: "N/A", line: 0 } }
    ].map(f => ({ ...f, sourceTier: 2 }));

    const allFindings = [...tier1, ...t2Findings];
    const severityMap = { "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": [] };
    allFindings.forEach(f => {
        const sev = f.severity?.toUpperCase() || "INFO";
        if (severityMap[sev]) severityMap[sev].push(f);
        else severityMap["INFO"].push(f);
    });

    return `
# 🔐 SentinelPR — Security Review

| Severity | Findings | Status |
| :--- | :--- | :--- |
${renderSeverityRow("CRITICAL", "Critical", severityMap)}
${renderSeverityRow("HIGH", "High", severityMap)}
${renderSeverityRow("MEDIUM", "Medium", severityMap)}
${renderSeverityRow("LOW", "Low", severityMap)}

---

## 🚨 Security issues identified that require attention

${renderSeverityGroup("🔴 Critical Priority", "CRITICAL", severityMap)}
${renderSeverityGroup("🟠 High Priority", "HIGH", severityMap)}
${renderSeverityGroup("🟡 Medium Priority", "MEDIUM", severityMap)}
${renderSeverityGroup("🔵 Low Priority", "LOW", severityMap)}
${renderSeverityGroup("⚪ Info / Advisory", "INFO", severityMap)}
`;
}

console.log(generateMockSummary());
