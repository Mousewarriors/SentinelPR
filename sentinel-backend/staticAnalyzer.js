import crypto from 'crypto';
import path from 'path';
import { TIER1_WARN_RULES } from './src/tier1/rules/warn/index.js';
import { TIER1_FAIL_RULES } from './src/tier1/rules/fail/index.js';

/**
 * Tier 1 Static Analysis Engine for SentinelPR
 * Version: 2.5 (Supply Chain + Full File Context)
 */

// --- 1. CORE UTILITIES ---

function computeEntropy(str) {
    const len = str.length;
    if (len === 0) return 0;
    const freqs = {};
    for (let char of str) freqs[char] = (freqs[char] || 0) + 1;
    let entropy = 0;
    for (let char in freqs) {
        let p = freqs[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

const REDACTION_PATTERNS = [/REDACTED/i, /<REDACTED>/i, /\*\*\*/, /your_token_here/i, /your_key_here/i, /your_password/i, /example/i, /dummy/i, /xxxxx/i];
function isRedacted(text) {
    return REDACTION_PATTERNS.some(p => p.test(text));
}

function globToRegex(glob) {
    if (typeof glob !== 'string') return /$./;
    let r = glob
        .replace(/[.+^${}()|[\]\\*?]/g, '\\$&')
        .replace(/\\\*\\\*/g, '@@ANY@@')
        .replace(/\\\*/g, '[^/\\\\]*')
        .replace(/\\\?/g, '.')
        .replace(/\\\{([^}]+)\\\}/g, (m, p1) => `(${p1.replace(/,/g, '|')})`)
        .replace(/@@ANY@@[\\\\/]/g, '(.*[\\\\/])?')
        .replace(/@@ANY@@/g, '.*');
    return new RegExp(`^${r}$`, 'i');
}

const DOCS_EXTENSIONS = ['.md', '.txt', '.rst', '.html', '.docx', '.pdf'];
const TEST_PATTERNS = [
    /\/__tests__\//i,
    /\.(test|spec)\.[a-z0-9]+$/i
];
const PROD_PATTERNS = [
    /\b(deploy|prod|production|infra|k8s|kubernetes|helm|terraform)\b/i,
    /\.env\.production/i,
    /config\/production/i,
    /\.github\/workflows/i
];

function shouldSkipLine(line, filePath, ruleId) {
    const text = line.text.trim();
    // 1. Comment filter
    if (/^(\/\/|#|\/\*|\*|<!--|--|;)/.test(text)) return true;

    // 2. Docs filter — skip markdown, plain text, etc.
    const ext = path.extname(filePath).toLowerCase();
    if (DOCS_EXTENSIONS.includes(ext)) return true;

    // 3. Test filter — only skip genuine test files (*.test.js, *.spec.ts, __tests__/)
    //    NOT entire directories named 'tests' — those may contain real source files.
    if (TEST_PATTERNS.some(p => p.test(filePath))) return true;

    // 4. Manual suppression
    if (text.includes(`sentinelpr:ignore ${ruleId}`)) return true;

    return false;
}

function matchesGlobs(path, globs) {
    if (!globs) return true;
    return globs.some(g => globToRegex(g).test(path));
}

// --- 2. DATA MODEL & FINGERPRINTING ---

export class FingerprintStore {
    constructor() { this.store = new Map(); }
    compute(ruleId, secretValue) {
        const normalized = secretValue.trim().replace(/^["']|["']$/g, '');
        return crypto.createHash('sha256').update(`${ruleId}:${normalized}`).digest('hex');
    }
    add(repoId, ruleId, fingerprint, commitSha) {
        if (!this.store.has(fingerprint)) {
            this.store.set(fingerprint, { repoId, ruleId, fingerprint, firstSeenCommitSha: commitSha, firstSeenAt: new Date().toISOString() });
            return true;
        }
        return false;
    }
    isKnown(fingerprint) { return this.store.has(fingerprint); }
}
export const globalFingerprintStore = new FingerprintStore();

// --- 3. DIFF PARSER ---

class UnifiedDiffParser {
    static parse(diffText) {
        if (!diffText) return [];
        const files = [];
        const lines = diffText.split(/\r?\n/);
        let currentFile = null;
        let currentHunk = null;

        for (let line of lines) {
            // Handle "diff --git" header to pre-create a file entry
            if (line.startsWith('diff --git ')) {
                // Extract filename from the b/ side: "diff --git a/foo b/foo"
                const match = line.match(/diff --git a\/(.+?) b\/(.+)$/);
                const filePath = match ? match[2] : 'unknown';
                currentFile = { path: filePath, hunks: [], addedLines: [], removedLines: [], contextLines: [], isDeleted: false };
                files.push(currentFile);
                currentHunk = null;
                continue;
            }
            if (line.startsWith('--- ')) {
                // '--- /dev/null' = new file, '--- a/path' = modified file
                // The file object was already created from the diff --git header, 
                // but if it wasn't (edge case), create it now
                if (!currentFile && !line.includes('/dev/null')) {
                    const filePath = line.startsWith('--- a/') ? line.substring(6) : line.substring(4);
                    currentFile = { path: filePath, hunks: [], addedLines: [], removedLines: [], contextLines: [], isDeleted: false };
                    files.push(currentFile);
                }
                continue;
            }
            if (line.startsWith('+++ ')) {
                if (line.includes('/dev/null') && currentFile) {
                    currentFile.isDeleted = true;
                } else if (currentFile && line.startsWith('+++ b/')) {
                    currentFile.path = line.substring(6); // finalise path from +++ b/ line
                }
                continue;
            }
            if (line.startsWith('@@')) {
                const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
                if (match && currentFile) {
                    currentHunk = { oldStart: parseInt(match[1], 10), newStart: parseInt(match[2], 10), lines: [] };
                    currentFile.hunks.push(currentHunk);
                }
                continue;
            }
            if (currentHunk) currentHunk.lines.push(line);
        }

        files.forEach(file => {
            file.hunks.forEach(hunk => {
                let currentNewLineNum = hunk.newStart;
                let currentOldLineNum = hunk.oldStart;
                hunk.lines.forEach(line => {
                    if (line.startsWith('+')) {
                        file.addedLines.push({ number: currentNewLineNum, text: line.substring(1) });
                        currentNewLineNum++;
                    } else if (line.startsWith('-')) {
                        file.removedLines.push({ number: currentOldLineNum, text: line.substring(1) });
                        currentOldLineNum++;
                    } else if (line.startsWith(' ')) {
                        // Context lines — store these so FAIL rules can scan pre-existing vulnerabilities
                        file.contextLines.push({ number: currentNewLineNum, text: line.substring(1) });
                        currentNewLineNum++;
                        currentOldLineNum++;
                    }
                });
            });
        });
        return files;
    }
}

// --- 5. MAIN ANALYZER CLASS ---

export class StaticAnalyzer {
    constructor(fingerprintStore = globalFingerprintStore) {
        this.fingerprintStore = fingerprintStore;
        this.rulesById = new Map();
        [...TIER1_FAIL_RULES, ...TIER1_WARN_RULES].forEach(r => { if (r && r.id) this.rulesById.set(r.id, r); });
    }

    analyzeDiff(diffText) {
        const files = UnifiedDiffParser.parse(diffText);
        let findings = [];

        files.forEach(file => {
            const isProdContext = PROD_PATTERNS.some(p => p.test(file.path));

            [...TIER1_FAIL_RULES, ...TIER1_WARN_RULES].forEach(rule => {
                if (!rule) return;
                if (rule.appliesTo && !matchesGlobs(file.path, rule.appliesTo.fileGlobs)) return;
                findings.push(...this._applyRule(file, rule, isProdContext));
            });
        });

        findings = this.applyCorrelationRules(findings);

        return { verdict: this.calculateVerdict(findings), findings: this.rankAndCapFindings(findings) };
    }

    applyCorrelationRules(findings) {
        const findingsRuleIds = new Set(findings.map(f => f.ruleId));
        const correlatedFindings = [...findings];

        TIER1_WARN_RULES.filter(r => r.correlation).forEach(rule => {
            const { requires, logic } = rule.correlation;
            let trigger = false;

            if (logic === "BOTH_PRESENT") {
                trigger = requires.every(id => findingsRuleIds.has(id));
            } else if (logic === "ANY_PRESENT") {
                trigger = requires.some(id => findingsRuleIds.has(id));
            }

            if (trigger) {
                // Find a representative snippet from the required findings
                const baseFinding = findings.find(f => requires.includes(f.ruleId)) || findings[0];
                correlatedFindings.push({
                    ruleId: rule.id, kind: rule.kind, severity: rule.severity, status: "NEW", ...rule.explanation,
                    file: baseFinding?.file || "PR_CONTEXT", line: baseFinding?.line || 1, snippet: "[CROSS-RULE CORRELATION]"
                });
            }
        });

        return correlatedFindings;
    }

    _applyRule(file, rule, isProdContext) {
        let findings = [];
        const spec = rule.detection;
        if (!spec) return findings;

        const mode = rule.appliesTo?.diffLines || "ADDED_ONLY";
        const linesToScan = (mode === "REMOVED_ONLY") ? file.removedLines : file.addedLines;

        const allLinesToScan = linesToScan;

        const targets = [...allLinesToScan];
        if (spec.type === "COMPOSITE") targets.push({ number: 1, text: "[FILE_CONTEXT]" });

        targets.forEach(line => {
            if (shouldSkipLine(line, file.path, rule.id)) return;

            // Trigger gating logic
            let trigger = false;
            if (spec.type === "REGEX") {
                trigger = this._checkRegex(line, spec);
            } else if (spec.type === "COMPOSITE") {
                trigger = this._checkComposite(file, line, spec.composite, isProdContext);
            }

            if (trigger) {
                if (rule.triggerPolicy?.ignoreIfLooksRedacted && isRedacted(line.text)) return;
                findings.push({
                    ruleId: rule.id, kind: rule.kind, severity: rule.severity, status: "NEW", ...rule.explanation,
                    file: file.path, line: line.number || 1, snippet: line.text.substring(0, 160).trim()
                });
            }
        });
        return findings;
    }

    _checkRegex(line, spec) {
        let trigger = spec.patterns.some(p => {
            if (p instanceof RegExp) return p.test(line.text);
            let { pattern, flags } = this._parsePattern(p);
            try {
                const re = new RegExp(pattern, flags);
                if (spec.requireValuePosition) {
                    const match = line.text.match(/[:=]\s*["']?([^"'\s]+)["']?/);
                    return match ? re.test(match[1]) : false;
                }
                return re.test(line.text);
            } catch (e) { return false; }
        });

        if (spec.negativePatterns && trigger) {
            if (spec.negativePatterns.some(p => {
                if (p instanceof RegExp) return p.test(line.text);
                let { pattern, flags } = this._parsePattern(p);
                try { return new RegExp(pattern, flags || 'i').test(line.text); } catch (e) { return false; }
            })) trigger = false;
        }
        return trigger;
    }

    _parsePattern(p) {
        let pattern = p;
        let flags = '';
        while (pattern.startsWith('(?')) {
            const nextChar = pattern.charAt(2);
            if (nextChar === 'i') { flags += 'i'; pattern = pattern.substring(4); }
            else if (nextChar === 'm') { flags += 'm'; pattern = pattern.substring(4); }
            else if (nextChar === 's') { flags += 's'; pattern = pattern.substring(4); }
            else break;
        }
        return { pattern, flags };
    }

    _hasNearSource(file, line, windowSize = 15) {
        const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < windowSize);
        const sourcePattern = /\b(req\.(query|body|params|headers|cookies|args|form)|request\.(args|form|values|json|body|headers)|ctx\.request|params\[|\$_GET|\$_POST)\b/i;
        return near.some(l => sourcePattern.test(l.text));
    }

    _hasNearGuard(file, line, windowSize = 20) {
        const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < windowSize);
        const guardPattern = /\b(sanitize|normalize|basename|realpath|filepath\.Clean|zod|pydantic|allowlist|whitelist|validate|filter|pick|omit|redact|mask)\b/i;
        return near.some(l => guardPattern.test(l.text));
    }

    _checkComposite(file, line, composite, isProdContext) {
        const evaluate = (h) => {
            // ... (existing evaluators)
            // Secrets Detectors
            if (h === "K8S_MANIFEST_CONTEXT") {
                return /(kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob|Service|ConfigMap|Secret))/i.test(file.addedLines.map(l => l.text).join('\n'));
            }
            if (h === "PRIVILEGED_TRUE") {
                return /privileged\s*:\s*true/i.test(line.text);
            }
            if (h === "K8S_POD_SPEC_CONTEXT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return near.some(l => /\b(spec|containers|template|pod)\b/i.test(l.text));
            }
            if (h === "HOST_NETWORK_TRUE") return /hostNetwork\s*:\s*true/i.test(line.text);
            if (h === "HOST_PID_TRUE") return /hostPID\s*:\s*true/i.test(line.text);
            if (h === "HOST_IPC_TRUE") return /hostIPC\s*:\s*true/i.test(line.text);

            if (h === "K8S_HOSTPATH_PRESENT") return /hostPath\s*:/i.test(line.text);
            if (h === "HOSTPATH_SENSITIVE_TARGET") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 5);
                return near.some(l => /\bpath\s*:\s*['"]?(\/|\/var\/run\/docker\.sock|\/etc|\/root|\/proc|\/sys)\b/i.test(l.text));
            }
            if (h === "RUN_AS_ROOT_TRUE") return /runAsNonRoot\s*:\s*false/i.test(line.text);
            if (h === "CAPABILITIES_ADDED") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 10);
                return near.some(l => /capabilities\s*:/i.test(l.text)) && near.some(l => /add\s*:/i.test(l.text));
            }

            if (h === "IAM_CONDITION_PRESENT") {
                return file.addedLines.some(l => Math.abs(l.number - line.number) < 20 && /Condition\s*[:=]/i.test(l.text));
            }

            if (h === "LLM_OUTPUT_PRESENT") {
                return /\b(modelOutput|llmOutput|completion|responseText|assistant|aiOutput|responseText)\b/i.test(line.text);
            }
            if (h === "DANGEROUS_EXEC_SINK") {
                return /\b(eval|exec|execSync|spawn|system|new Function)\b\s*\(/.test(line.text);
            }

            if (h === "CSRF_DISABLED_SIGNALS") {
                return /\b(DISABLE_CSRF=true|csrf\s*[:=]\s*false|disableCsrf\s*[:=]\s*true)\b/i.test(line.text);
            }
            if (h === "COOKIE_AUTH_MARKERS_PRESENT") {
                return file.addedLines.some(l => /\b(set-cookie|session|cookieParser|express-session|cookie-session)\b/i.test(l.text));
            }
            if (h === "COOKIE_FLAGS_WEAK") {
                const text = line.text.toLowerCase();
                return !(text.includes("secure: true") && text.includes("httponly: true"));
            }

            if (h === "FILE_IO_SINK") {
                return /\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|rm|open|sendFile|send_file|FileResponse)\b\s*\(/.test(line.text);
            }

            if (h === "SSL_VERIFY_DISABLED") {
                return /\b(rejectUnauthorized\s*[:=]\s*false|verify\s*[:=]\s*False|InsecureSkipVerify\s*[:=]\s*true)\b/i.test(line.text);
            }
            if (h === "DESERIALIZATION_SINK") {
                return /\b(pickle\.loads|unserialize|Marshal\.load|ObjectInputStream|readObject|serialize\.unserialize)\b\s*\(/.test(line.text);
            }

            // --- Original evaluators follow ---
            if (h === "SECRET_KEYWORD_NEAR_ASSIGNMENT") {
                return /(secret|token|password|key|auth|api|client).{0,30}[:=]/i.test(line.text);
            }
            if (h === "HIGH_ENTROPY_VALUE") {
                const valMatch = line.text.match(/[:=]\s*["']?([A-Za-z0-9+/=]{16,})["']?/);
                if (!valMatch) return false;
                const val = valMatch[1];
                const entropy = computeEntropy(val);
                // Entropy Gate 2.0: Sliding scale
                if (val.length <= 24) return entropy > 4.1;
                if (val.length <= 40) return entropy > 3.8;
                return entropy > 3.6;
            }
            if (h === "HAS_NEAR_SOURCE") {
                return this._hasNearSource(file, line);
            }
            if (h === "HAS_NEAR_GUARD") {
                return this._hasNearGuard(file, line);
            }
            if (h === "IS_PROD_CONTEXT") {
                return isProdContext;
            }
            if (h === "ENV_VALUE_HAS_ENTROPY") {
                const valMatch = line.text.match(/[:=]\s*["']?([A-Za-z0-9+/=]{16,})["']?/);
                return valMatch ? computeEntropy(valMatch[1]) > 3.5 : false;
            }
            if (h === "JWT_LIKE_TOKEN") {
                return /eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/.test(line.text);
            }
            if (h === "PATH_LOOKS_TEST_OR_FIXTURE") {
                return /(test|spec|fixture|mock|dummy)/i.test(file.path);
            }
            if (h === "KEYWORD_SMTP_CONTEXT") {
                return /(smtp|mail|sendgrid|mailgun)/i.test(line.text);
            }
            if (h === "KEYWORD_REDIS_CONTEXT") {
                return /(redis|cache|ioredis)/i.test(line.text);
            }
            if (h === "LINE_IS_COMMENT") {
                return /^(\s*)(\/\/|#|\/\*|--)/.test(line.text);
            }
            if (h === "HIGH_ENTROPY_VALUE_OR_JWT") {
                return evaluate("HIGH_ENTROPY_VALUE") || evaluate("JWT_LIKE_TOKEN");
            }
            if (h === "FILENAME_LOOKS_PRIVATE_KEY") {
                return /id_rsa|id_ecdsa|id_ed25519|id_dsa|private|key\.pem/i.test(file.path);
            }
            if (h === "VALUE_IS_NON_EMPTY_LITERAL") {
                const match = line.text.match(/[:=]\s*["']([^"']{2,})["']/);
                return !!match;
            }
            if (h === "LINE_LOOKS_DOCS") {
                return /\.(md|txt|rst|html)$/i.test(file.path) || line.text.includes("Example:") || line.text.includes("Usage:");
            }
            if (h === "K8S_KIND_SECRET") {
                return file.addedLines.some(l => Math.abs(l.number - line.number) < 20 && l.text.includes("kind: Secret"));
            }
            if (h === "K8S_DATA_KEYS_PRESENT") {
                return line.text.includes("data:") || line.text.includes("stringData:");
            }
            if (h === "ENV_FILE_MULTIPLE_KEYS_SAME_VALUE") {
                const valMatch = line.text.match(/[:=]\s*(.+)$/);
                if (!valMatch) return false;
                const val = valMatch[1].trim().replace(/^["']|["']$/g, '');
                if (val.length < 10) return false;
                return file.addedLines.filter(l => l.text.includes(val)).length >= 2;
            }

            // XML XXE Detectors
            if (h === "XML_NOENT_TRUE") {
                return /(noent|expandEntities|externalEntities|dtd)\s*[:=]\s*true/i.test(line.text);
            }
            if (h === "XML_USER_SINK") {
                return /\b(parse|load|parseString|read)\b.*req\.(query|body|params)/i.test(line.text);
            }

            // Auth Detectors
            if (h === "COOKIE_SET_PRESENT") {
                return /(setCookie|Set-Cookie|res\.cookie|cookie\.set)/i.test(line.text);
            }
            if (h === "COOKIE_FLAGS_MISSING_OR_WEAK") {
                const text = line.text.toLowerCase();
                return !(text.includes("secure: true") && text.includes("httponly: true"));
            }
            if (h === "JWT_VERIFY_OPTIONS_WEAK") {
                return /verify\(.*\{.*(ignoreExpiration|algorithms).*true/i.test(line.text);
            }
            if (h === "JWT_ALG_NONE_ALLOWED") {
                return /algorithm.*none/i.test(line.text) || /algorithms.*\[.*none.*\]/i.test(line.text);
            }
            if (h === "ROUTE_DEFINITION_PRESENT") {
                return /\.(get|post|all|use|put|delete|patch)\(['"]\//.test(line.text);
            }
            if (h === "AUTH_MIDDLEWARE_NOT_PRESENT_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 8);
                return !near.some(l => /(auth|ensureAuthenticated|requireLogin|passport\.authenticate)/i.test(l.text));
            }
            if (h === "CORS_WILDCARD") {
                return /Access-Control-Allow-Origin.*[\*]/.test(line.text) || /origin.*[\*]/.test(line.text);
            }
            if (h === "CORS_WILDCARD_WITH_CREDENTIALS") {
                return evaluate("CORS_WILDCARD") && file.addedLines.some(l => Math.abs(l.number - line.number) < 5 && /credentials.*true/i.test(l.text));
            }
            if (h === "RESET_TOKEN_LOGGED") {
                return /(console\.log|logger|print).*resetToken/i.test(line.text);
            }
            if (h === "RESET_TOKEN_RETURNED_IN_RESPONSE") {
                return /res\.(send|json|write).*resetToken/i.test(line.text);
            }
            if (h === "RESET_LINK_HTTP") {
                return /http:\/\/.*(reset|password|token)/i.test(line.text);
            }
            if (h === "RESET_LINK_TOKEN_WEAK_CONTEXT") {
                return /['"`](.*\/)?reset.*(\?|&|#)token=/i.test(line.text);
            }
            if (h === "REDIRECT_PARAM_PRESENT") {
                return /req\.(query|body|params)\.(redirect|url|next|callback|target|returnTo)/i.test(line.text);
            }
            if (h === "REDIRECT_TARGET_FROM_REQUEST") {
                return /(redirect|location|url|next|callback|returnTo).{0,20}req\.(query|body|params)/i.test(line.text);
            }
            if (h === "SENSITIVE_ACTION_KEYWORDS") {
                return /\b(delete|update|remove|permission|grant|admin|billing|payout|invoice)\b/i.test(line.text);
            }
            if (h === "NO_AUTHZ_KEYWORDS_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 10);
                return !near.some(l => /\b(auth|authorize|authz|role|permission|check|ensure|require|policy)\b/i.test(l.text));
            }
            if (h === "COOKIE_SAMESITE_NONE_PRESENT") {
                return /sameSite.*none/i.test(line.text);
            }
            if (h === "COOKIE_SECURE_NOT_PRESENT_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 5);
                return !near.some(l => /secure.*true/i.test(l.text));
            }
            if (h === "LOGIN_FLOW_KEYWORDS") {
                return /\b(login|authenticate|signin|session|authorize|auth|passport|oauth)\b/i.test(line.text);
            }
            if (h === "NO_SESSION_REGEN_KEYWORDS") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 15);
                return !near.some(l => /\b(regenerate|rotate|destroy|clear|newSession|save)\b/i.test(l.text));
            }
            if (h === "OAUTH_AUTHORIZE_FLOW") {
                return /\boauth\b/i.test(line.text) && /\b(authorize|auth|callback)\b/i.test(line.text);
            }
            if (h === "OAUTH_STATE_NOT_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return !near.some(l => /\bstate\b/i.test(l.text));
            }
            if (h === "SENSITIVE_ROUTE_KEYWORDS") {
                return /\b(admin|billing|payout|invoice|internal|debug|config|setup)\b/i.test(line.text);
            }
            if (h === "AUTH_ENDPOINT_KEYWORDS") {
                return /\b(login|signin|reset|password|otp|mfa|forgot)\b/i.test(line.text);
            }
            if (h === "NO_RATE_LIMIT_KEYWORDS_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 15);
                return !near.some(l => /\b(rateLimit|limit|throttle|quota|delay|burst)\b/i.test(l.text));
            }
            if (h === "GRAPHQL_QUERY_STRING_BUILT_DYNAMically") {
                return /gql`.*\$\{/i.test(line.text) || (/\b(query|mutation)\b/i.test(line.text) && (line.text.includes("${") || line.text.includes("+")));
            }
            if (h === "GRAPHQL_EXECUTE_PRESENT") {
                return /\b(graphql|execute|query|mutate)\b\s*\(/i.test(line.text);
            }
            if (h === "TEMPLATE_RENDER_CALL") {
                return /\b(render|compile|template|partial)\b\s*\(/.test(line.text);
            }
            if (h === "TEMPLATE_STRING_FROM_REQUEST") {
                return /\b(render|compile)\b.*req\.(query|body|params)/.test(line.text);
            }
            // CI Heuristics
            if (h === "WORKFLOW_EVENT_PULL_REQUEST_TARGET") {
                return /pull_request_target\s*:/i.test(line.text);
            }
            if (h === "ACTIONS_CHECKOUT_PRESENT") {
                return /uses\s*:\s*actions\/checkout/i.test(line.text);
            }
            if (h === "CHECKOUT_REF_UNTRUSTED_OR_MISSING") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 15);
                const hasSafeRef = near.some(l => /ref\s*:\s*(\${{\s*github\.(event\.pull_request\.base\.sha|sha)\s*}}|\b(main|master|stable)\b)/i.test(l.text));
                const hasRef = near.some(l => /ref\s*:/i.test(l.text));
                return !hasSafeRef;
            }
            if (h === "SECRETS_CONTEXT_REFERENCED") {
                return /\${{\s*secrets\./i.test(line.text);
            }
            if (h === "CHECKOUT_PERSIST_CREDENTIALS_TRUE_OR_MISSING") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 15);
                const explicitFalse = near.some(l => /persist-credentials\s*:\s*false/i.test(l.text));
                return !explicitFalse;
            }
            if (h === "WORKFLOW_EVENT_PULL_REQUEST") {
                return /pull_request\s*:/i.test(line.text) && !/pull_request_(target|review)/i.test(line.text);
            }
            if (h === "NO_FORK_GUARD_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 40);
                return !near.some(l => /github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository/i.test(l.text));
            }
            if (h === "WORKFLOW_EVENT_WORKFLOW_DISPATCH") {
                return /workflow_dispatch\s*:/i.test(line.text);
            }
            if (h === "WORKFLOW_INPUTS_DEFINED") {
                return /inputs\s*:/i.test(line.text);
            }
            if (h === "RUN_USES_INPUTS_INTERPOLATION") {
                return /run\s*:.*(\${{\s*inputs\.|github\.event\.inputs\.)/i.test(line.text);
            }
            if (h === "WORKFLOW_HAS_MUTATING_STEPS") {
                const text = line.text.toLowerCase();
                return /\b(deploy|publish|push|upload|sync|terraform|aws|gcloud|docker\s+push)\b/i.test(text);
            }
            if (h === "NO_CONCURRENCY_BLOCK_PRESENT") {
                return !file.addedLines.some(l => /concurrency\s*:/i.test(l.text));
            }
            if (h === "ACTIONS_CACHE_USED") {
                return /uses\s*:\s*actions\/cache/i.test(line.text);
            }
            if (h === "CACHE_KEY_FROM_UNTRUSTED_CONTEXT") {
                return /key\s*:.*(\${{\s*github\.event\.|github\.head_ref)/i.test(line.text);
            }
            if (h === "ACTIONS_DOWNLOAD_ARTIFACT_USED") {
                return /uses\s*:\s*actions\/download-artifact/i.test(line.text);
            }
            if (h === "EXECUTES_DOWNLOADED_CONTENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return near.some(l => /\brun\s*:\s*.*(\.\/|\bbash\b|\bsh\b|\bnode\b|\bpython\b)/i.test(l.text));
            }
            if (h === "CHECKOUT_REF_FROM_EVENT_OR_INPUTS") {
                return /ref\s*:\s*\${{\s*(github\.event|inputs\.)/i.test(line.text);
            }
            // Supply Chain Heuristics
            if (h === "FILE_DELETED") {
                return file.isDeleted === true;
            }
            if (h === "DEPENDENCY_DECLARATION_LINE") {
                return /"[a-z0-9_.-]+"|\b(gem|pip|composer|requirement|dependency)\b/i.test(line.text);
            }
            if (h === "VERSION_RANGE_IS_LOOSE") {
                return /\^|~|\*|>=|dev-/.test(line.text);
            }
            if (h === "LOCKFILE_CHANGED_MANY_LINES") {
                return (file.addedLines.length + file.removedLines.length) > 1000;
            }
            // File Upload Heuristics
            if (h === "UPLOAD_HANDLER_PRESENT") {
                return /\b(upload|multer|busboy|formidable|multipart|request\.file)\b/i.test(line.text);
            }
            if (h === "NO_MIME_ALLOWLIST_KEYWORDS_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 40);
                return !near.some(l => /\b(mime|type|content-type|accept|allowlist|whitelist)\b/i.test(l.text));
            }
            if (h === "NO_EXTENSION_ALLOWLIST_KEYWORDS_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 40);
                return !near.some(l => /\b(extension|ext|allowlist|whitelist|regex|match)\b/i.test(l.text));
            }
            if (h === "NO_SIZE_LIMIT_KEYWORDS_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 40);
                return !near.some(l => /\b(limit|size|max|length|bytes)\b/i.test(l.text));
            }
            if (h === "UPLOAD_FILENAME_USED") {
                return /\b(filename|originalname|client_filename|file\.name)\b/i.test(line.text);
            }
            if (h === "NO_SANITIZATION_KEYWORDS_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return !near.some(l => /\b(sanitize|normalize|basename|replace|path\.resolve|realpath)\b/i.test(l.text));
            }
            // IaC & Cloud Heuristics (Cross-line detection)
            if (h === "TF_SG_WORLD_OPEN") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return near.some(l => /cidr_blocks\s*=\s*\[[^\]]*("0\.0\.0\.0\/0"|"::\/0")[^\]]*\]/i.test(l.text));
            }
            if (h === "TF_SG_SENSITIVE_PORT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return near.some(l => /\b(from_port|to_port)\s*=\s*(22|2375|3306|5432|6379|27017|9200)\b/i.test(l.text));
            }
            if (h === "CF_SG_WORLD_OPEN") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return near.some(l => /CidrIp\s*:\s*(0\.0\.0\.0\/0|"::\/0")/i.test(l.text));
            }
            if (h === "CF_SG_SENSITIVE_PORT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return near.some(l => /\b(FromPort|ToPort)\s*:\s*(22|2375|3306|5432|6379|27017|9200)\b/i.test(l.text));
            }
            if (h === "IAM_ACTION_WILDCARD") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 25);
                return near.some(l => /Action\s*[:=]\s*"\*"/i.test(l.text));
            }
            if (h === "IAM_RESOURCE_WILDCARD") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 25);
                return near.some(l => /Resource\s*[:=]\s*"\*"/i.test(l.text));
            }
            // Serverless Heuristics
            if (h === "SERVERLESS_FUNCTION_PRESENT") {
                return /\b(lambda|function|cloudfunctions|cloud run|serverless)\b/i.test(line.text) || /\.(yml|yaml|json|tf)$/i.test(file.path);
            }
            if (h === "LOGGING_CALL_PRESENT") {
                return /\b(console\.log|logger|print|puts|log|info|warn|error)\b\s*\(/.test(line.text);
            }
            if (h === "SENSITIVE_FIELD_NAME_PRESENT") {
                return /\b(token|cookie|auth|password|secret|key|email|user|api_key)\b/i.test(line.text);
            }
            if (h === "SERVERLESS_HANDLER_PRESENT") {
                return /\b(exports\.handler|handler|Request|Response|GET|POST|router)\b/i.test(line.text);
            }
            if (h === "NO_AUTH_MARKER_KEYWORDS_PRESENT_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 40);
                return !near.some(l => /\b(auth|authenticate|authorize|guard|jwt|passport|login|session|verify|restrict)\b/i.test(l.text));
            }
            if (h === "SERVERLESS_PROXY_HANDLER_PRESENT") {
                return /\b(fetch|axios|request|http\.get|http\.request|node-fetch)\b/i.test(line.text);
            }
            if (h === "USER_CONTROLLED_URL_USED") {
                return /\b(url|target|dest|uri)\b.*req\.(query|body|params)/i.test(line.text);
            }
            if (h === "NO_ALLOWLIST_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 30);
                return !near.some(l => /\b(allowlist|whitelist|permitted|allowed|validOrigins)\b/i.test(l.text));
            }
            if (h === "LAMBDA_VPC_CONFIG_PRESENT") {
                return /\b(VpcConfig|vpc_config|subnets|security_group_ids)\b/i.test(line.text);
            }
            if (h === "SECURITY_GROUP_EGRESS_WIDE_OPEN_PRESENT") {
                return /0\.0\.0\.0\/0/i.test(line.text) && /\begress\b/i.test(line.text);
            }
            if (h === "ASYNC_INVOCATION_CONFIG_PRESENT") {
                return /\b(EventInvokeConfig|aws_lambda_function_event_invoke_config|async)\b/i.test(line.text);
            }
            if (h === "NO_FAILURE_DESTINATION_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return !near.some(l => /\b(onFailure|destination|DeadLetterConfig|DLQ|target|sqs|sns)\b/i.test(l.text));
            }
            if (h === "EVENT_SOURCE_MAPPING_PRESENT") {
                return /\b(EventSourceMapping|event_source_mapping|trigger|s3|sns|sqs|schedule)\b/i.test(line.text);
            }
            if (h === "NO_FILTERING_PRESENT_OR_WILDCARD_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return !near.some(l => /\b(filter|FilterCriteria|prefix|suffix|pattern)\b/i.test(l.text));
            }
            if (h === "LAMBDA_CONTAINER_IMAGE_REFERENCE_PRESENT") {
                return /\b(ImageUri|image_uri|Image)\b\s*[:=]/i.test(line.text);
            }
            if (h === "IMAGE_REFERENCE_HAS_NO_DIGEST") {
                return !/@sha256:/.test(line.text);
            }
            if (h === "WRITABLE_TMP_OR_WORKDIR_USED") {
                return /\b(\/tmp|tempdir|os\.tmpdir|working_directory)\b/i.test(line.text);
            }
            if (h === "SERVED_STATIC_FROM_PATH_PRESENT") {
                return /\b(static|serve|sendFile|send_file|express.static)\b/i.test(line.text);
            }
            // Web Security Heuristics
            if (h === "CORS_WILDCARD_PRESENT") {
                return /Access-Control-Allow-Origin\s*:\s*\*|origin\s*[:=]\s*['"]\*['"]|allow_origin\s*[:=]\s*\*/i.test(line.text);
            }
            if (h === "CORS_CREDENTIALS_TRUE_PRESENT") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return near.some(l => /Access-Control-Allow-Credentials\s*:\s*true|allowCredentials\s*[:=]\s*true|credentials\s*[:=]\s*true/i.test(l.text));
            }
            if (h === "STATE_CHANGING_ROUTE_PRESENT") {
                return /\b(router|app|api|route)\.(post|put|patch|delete)\b/i.test(line.text);
            }
            if (h === "NO_CSRF_KEYWORDS_PRESENT_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 60);
                // Try to ignore common comment patterns or require more specific keywords
                return !near.some(l => !l.text.trim().startsWith("//") && !l.text.trim().startsWith("*") && /\b(csrf|xsrf|forgery|protect|antiforgery)\b/i.test(l.text));
            }
            if (h === "SAMESITE_NONE_PRESENT") {
                return /samesite\s*[:=]\s*['"]?none['"]?/i.test(line.text);
            }
            if (h === "SECURE_FALSE_OR_MISSING_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 20);
                return !near.some(l => /\bsecure\s*[:=]\s*true\b/i.test(l.text));
            }
            if (h === "ADMIN_ROUTE_PATTERN_PRESENT") {
                return /\b(admin|dashboard|manage|internal)\b/i.test(line.text) && /\b(router|app|get|post)\b/i.test(line.text);
            }
            if (h === "NO_AUTH_GUARD_KEYWORDS_PRESENT_NEARBY") {
                const near = file.addedLines.filter(l => Math.abs(l.number - line.number) < 40);
                return !near.some(l => !l.text.trim().startsWith("//") && !l.text.trim().startsWith("*") && /\b(auth|authenticate|authorize|guard|ensureAuthenticated|passport|jwt)\b/i.test(l.text));
            }
            return false;
        };

        if (composite.allOf) return composite.allOf.every(evaluate);
        if (composite.anyOf) return composite.anyOf.some(evaluate);
        return false;
    }

    rankAndCapFindings(findings) {
        const deduped = [];
        const seen = new Set();
        findings.forEach(f => {
            const key = `${f.ruleId}:${f.file}:${f.line}`;
            if (!seen.has(key)) { deduped.push(f); seen.add(key); }
        });
        const severityOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3 };
        return deduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]).slice(0, 15);
    }

    calculateVerdict(findings) {
        if (findings.some(f => f.kind === "FAIL")) return "FAIL";
        if (findings.length > 0) return "WARN";
        return "PASS";
    }
}

export function runTier1Analysis(diff) {
    const analyzer = new StaticAnalyzer();
    const result = analyzer.analyzeDiff(diff);

    // Transform to match server.js expectations
    return result.findings.map(f => ({
        id: f.ruleId,
        title: f.title || f.ruleId,
        severity: f.severity,
        description: f.description || f.ruleId,
        recommended_fix: f.recommendation || "Review the flagged line.",
        location: {
            path: f.file,
            start_line: f.line,
            end_line: f.line
        },
        evidence: {
            snippet: f.snippet
        }
    }));
}
