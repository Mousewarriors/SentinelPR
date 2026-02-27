/**
 * File Uploads & Path Traversal WARN rules
 *
 * Philosophy:
 * - File upload flows are a major SaaS attack surface.
 * - These are WARN because many cases depend on surrounding validation,
 *   storage layers, and infra controls.
 */

export const F901_SAVE_UPLOAD_USER_FILENAME = {
    id: "F901_SAVE_UPLOAD_USER_FILENAME",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**", "**/routes/**", "**/controllers/**"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["upload", "multipart", "file", "filename", "save", "write"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(filename|originalname|client_filename|upload\\.filename|file\\.name)\\b[^\\n]{0,120}\\b(writeFile|write|save|store|putObject|File\\.open|open\\()\\b", "(?i)\\b(writeFile|save|store|putObject)\\b[^\\n]{0,120}\\b(filename|originalname|client_filename|file\\.name)\\b"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Upload storage", shortLabel: "User filename", maxFindingsPerPR: 3, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Upload saved using user-controlled filename", description: "Code appears to save an uploaded file using a filename derived from user input.", risk: "User-controlled filenames can enable path traversal, overwriting files, or storing executable content under dangerous names.", confidenceRationale: "Heuristic: depends on whether sanitization, storage isolation, and safe naming are applied elsewhere.", recommendation: "Generate server-side filenames (UUIDs), store uploads outside web roots, and preserve the original name only as metadata after sanitization." }
};

export const F902_UPLOAD_NO_CONTENT_TYPE_ALLOWLIST = {
    id: "F902_UPLOAD_NO_CONTENT_TYPE_ALLOWLIST",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["content-type", "mimetype", "mime", "upload", "file"], withinChars: 260 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["UPLOAD_HANDLER_PRESENT", "NO_MIME_ALLOWLIST_KEYWORDS_PRESENT"], withinSameHunk: true, withinLines: 160 } },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Validation", shortLabel: "No MIME allowlist", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Upload handler without obvious MIME allowlist", description: "Upload handling code was added/modified without obvious content-type allowlisting nearby.", risk: "Accepting arbitrary content types increases risk of uploading executable or dangerous content and bypassing downstream scanning.", confidenceRationale: "Heuristic: allowlists may exist in shared middleware or config files.", recommendation: "Enforce a strict allowlist of MIME types and verify content by sniffing magic bytes where possible." }
};

export const F903_UPLOAD_NO_EXTENSION_ALLOWLIST = {
    id: "F903_UPLOAD_NO_EXTENSION_ALLOWLIST",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["extension", "ext", "filename", "upload", "file"], withinChars: 260 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["UPLOAD_HANDLER_PRESENT", "NO_EXTENSION_ALLOWLIST_KEYWORDS_PRESENT"], withinSameHunk: true, withinLines: 160 } },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Validation", shortLabel: "No ext allowlist", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Upload handler without obvious extension allowlist", description: "Upload handling code was added/modified without obvious file extension allowlisting nearby.", risk: "Allowing arbitrary extensions can enable script uploads (e.g., .php, .jsp) and polyglot attacks.", confidenceRationale: "Heuristic: some systems enforce allowlists at routing, storage, or reverse proxy layers.", recommendation: "Enforce an extension allowlist, normalize filenames, and treat extensions as untrusted unless verified by content sniffing." }
};

export const F904_UPLOAD_SIZE_LIMIT_MISSING = {
    id: "F904_UPLOAD_SIZE_LIMIT_MISSING",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["upload", "multipart", "limit", "max", "size"], withinChars: 260 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["UPLOAD_HANDLER_PRESENT", "NO_SIZE_LIMIT_KEYWORDS_PRESENT"], withinSameHunk: true, withinLines: 200 } },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "DoS", shortLabel: "No size limit", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Upload handler without obvious size limits", description: "Upload handling code was added without obvious maximum size enforcement nearby.", risk: "Missing size limits can enable denial-of-service via large uploads (memory/disk exhaustion) and slow upload attacks.", confidenceRationale: "Heuristic: limits may be enforced by reverse proxy (nginx) or framework-level configuration elsewhere.", recommendation: "Set upload size limits at multiple layers (app + proxy) and reject oversized uploads early." }
};

export const F905_UPLOAD_TO_WEB_ROOT = {
    id: "F905_UPLOAD_TO_WEB_ROOT",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\b(public|wwwroot|htdocs|static|assets|public_html)\\b[^\\n]{0,80}\\b(upload|uploads)\\b", "(?i)\\b(upload|uploads)\\b[^\\n]{0,80}\\b(public|wwwroot|htdocs|public_html)\\b"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Storage", shortLabel: "Web root", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Uploads may be stored under a web-served directory", description: "Paths suggest uploaded files may be stored under directories commonly served directly by the web server.", risk: "Storing uploads under web roots can enable direct access to malicious files, script execution, and content spoofing.", confidenceRationale: "Directory names are suggestive; exact serving behavior depends on deployment setup.", recommendation: "Store uploads outside web roots and serve through controlled download endpoints with content disposition and allowlists." }
};

export const F906_PATH_JOIN_WITH_USER_INPUT = {
    id: "F906_PATH_JOIN_WITH_USER_INPUT",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}", "**/pages/api/**", "**/app/api/**", "**/routes/**", "**/controllers/**"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["path", "join", "resolve", "dirname", "filename", "file"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(path\\.join|path\\.resolve|filepath\\.Join|File\\.join|File\\.expand_path|os\\.path\\.join|Path\\()\\b[^\\n]{0,160}\\b(req\\.(params|query|body)|params\\[|request\\.|input\\()"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Traversal", shortLabel: "Path join input", maxFindingsPerPR: 5, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "File path constructed from request input", description: "A filesystem path appears built using values derived from request/user input.", risk: "If not normalized and restricted, attackers can use path traversal to read/write/delete unintended files.", confidenceRationale: "Heuristic: safe implementations may validate and restrict the final path, but this pattern warrants review.", recommendation: "Use allowlisted identifiers mapped to server-side paths. Normalize and enforce that resolved paths remain within an expected base directory." }
};

export const F907_DIRECTORY_TRAVERSAL_REGEX_ONLY = {
    id: "F907_DIRECTORY_TRAVERSAL_REGEX_ONLY",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["..", "traversal", "sanitize", "replace", "regex", "path"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)replace\\([^\\)]*\\.\\.[^\\)]*\\)", "(?i)regex[^\\n]{0,120}\\.{2}", "(?i)\\.{2}\\/|\\.{2}\\\\"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Traversal", shortLabel: "Regex sanitize", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Path traversal prevention may rely on regex-only sanitization", description: "Code appears to attempt path traversal prevention via string replace/regex logic.", risk: "Regex-only sanitization is commonly bypassed via encoding, separator tricks, and normalization edge cases.", confidenceRationale: "Heuristic: true safety requires canonicalization + base-directory enforcement.", recommendation: "Canonicalize paths (resolve/realpath) and enforce they remain within an expected base directory; avoid ad-hoc regex sanitization." }
};

export const F908_SERVE_FILE_FROM_USER_PATH = {
    id: "F908_SERVE_FILE_FROM_USER_PATH",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["sendFile", "send_file", "FileResponse", "readFile", "download", "stream"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(sendFile|send_file|FileResponse|download|sendfile)\\b[^\\n]{0,200}\\b(req\\.(params|query)|params\\[|request\\.|input\\()"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Serving files", shortLabel: "Serve user path", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "File serving may use user-controlled path", description: "A file download/serve operation appears to use a path derived from request input.", risk: "This can enable path traversal and unintended file disclosure.", confidenceRationale: "Heuristic: safe implementations map IDs to files and restrict path roots.", recommendation: "Serve files by immutable IDs with server-side lookup. Enforce base directory constraints and use framework safe file serving APIs." }
};

export const F909_ARCHIVE_EXTRACT_PATH_TRAVERSAL = {
    id: "F909_ARCHIVE_EXTRACT_PATH_TRAVERSAL",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["zip", "tar", "extract", "unzip", "archive"], withinChars: 220 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(extractall|extract|unzip|ZipFile|tarfile)\\b"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Archives", shortLabel: "Archive extract", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Archive extraction added/modified (zip-slip risk)", description: "Code performs archive extraction (zip/tar), which commonly introduces zip-slip path traversal if not validated.", risk: "Malicious archives can write files outside the intended directory (zip-slip), leading to file overwrite and potential code execution.", confidenceRationale: "Archive extraction is a known high-risk pattern; safety depends on validating entry paths and extraction targets.", recommendation: "Validate archive entry paths, block absolute paths and '..', and enforce that extracted paths remain within a target directory." }
};

export const F910_ZIP_SLIP_PATTERNS = {
    id: "F910_ZIP_SLIP_PATTERNS",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\.{2}\\/|\\.{2}\\\\", "(?i)zip\\s*slip"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Archives", shortLabel: "Traversal entries", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Potential zip-slip traversal strings present", description: "Archive-related code references traversal patterns like '../' or '..\\'.", risk: "If used in archive entry names or extraction logic, traversal can overwrite or create files outside the intended directory.", confidenceRationale: "Traversal patterns are explicit; exact exploitability depends on the extraction implementation.", recommendation: "Reject any archive entries with traversal or absolute paths and enforce extraction under a fixed, canonical directory." }
};

export const F911_TAR_EXTRACT_UNSAFE = {
    id: "F911_TAR_EXTRACT_UNSAFE",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{py}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["tarfile", "extract", "extractall"], withinChars: 200 } },
    detection: { type: "REGEX", patterns: ["\\btarfile\\.open\\(", "\\.extractall\\(", "\\.extract\\("] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Archives", shortLabel: "tar extract", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Python tar extraction added (path traversal risk)", description: "Python tarfile extraction code was added/modified.", risk: "Tar archives can contain traversal paths and symlinks; unsafe extraction can overwrite files outside the destination.", confidenceRationale: "tarfile extraction usage is clear; safety depends on validating members before extraction.", recommendation: "Validate tar members (no absolute paths, no '..', handle symlinks/hardlinks safely) and enforce destination directory constraints." }
};

export const F912_TEMPFILE_INSECURE_USAGE = {
    id: "F912_TEMPFILE_INSECURE_USAGE",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["tmp", "temp", "tempfile", "/tmp", "TMPDIR"], withinChars: 220 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b/tmp\\b", "(?i)tempfile", "(?i)mktemp\\b", "(?i)createTempFile\\("] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Temp files", shortLabel: "Temp usage", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Temporary file usage requires safe handling", description: "Code uses temporary directories/files where insecure patterns can lead to symlink attacks or data exposure.", risk: "Insecure temp file creation can allow file overwrite via symlinks or leak sensitive intermediate files.", confidenceRationale: "Temp usage is detectable, but safety depends on using secure APIs (mkstemp) and correct permissions.", recommendation: "Use secure temp APIs, ensure restrictive permissions, and avoid predictable filenames in shared temp directories." }
};

export const F913_FILENAME_NOT_SANITIZED = {
    id: "F913_FILENAME_NOT_SANITIZED",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["filename", "originalname", "sanitize", "basename", "path"], withinChars: 260 } },
    detection: { type: "COMPOSITE", composite: { allOf: ["UPLOAD_FILENAME_USED", "NO_SANITIZATION_KEYWORDS_PRESENT"], withinSameHunk: true, withinLines: 120 } },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Validation", shortLabel: "No sanitize", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Filename used without obvious sanitization", description: "Upload filename appears used without obvious normalization/sanitization nearby.", risk: "Unsanitized filenames can include traversal sequences, unicode tricks, or dangerous extensions.", confidenceRationale: "Heuristic: sanitization may exist in shared helpers; still worth review.", recommendation: "Normalize filenames, strip path separators, enforce allowlisted extensions, and generate server-side storage names." }
};

export const F914_MULTIPART_PARSING_DEBUG = {
    id: "F914_MULTIPART_PARSING_DEBUG",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "LOW", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml,env}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["multipart", "upload", "busboy", "multer", "formidable"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)debug\\s*[:=]\\s*(true|1)", "(?i)verbose\\s*[:=]\\s*(true|1)"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Debug", shortLabel: "Upload debug", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Verbose/debug multipart logging enabled", description: "Multipart/upload parsing debug or verbose logging may be enabled.", risk: "Verbose upload logging can leak file contents, filenames, and sensitive form fields into logs.", confidenceRationale: "Debug toggles are explicit; impact depends on environment.", recommendation: "Disable verbose multipart logging in production and ensure sensitive fields are redacted." }
};

export const F915_IMAGE_PROCESSING_UNTRUSTED = {
    id: "F915_IMAGE_PROCESSING_UNTRUSTED",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["image", "resize", "thumbnail", "convert", "imagemagick", "sharp", "pillow"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)imagemagick|convert\\s+|sharp\\(|PIL\\.|pillow|libvips"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Parsers", shortLabel: "Image parse", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Untrusted image processing added/modified", description: "Code processes uploaded images using image libraries or tools.", risk: "Image parsers can have memory corruption and DoS vulnerabilities; unsafe pipelines can also enable SSRF (e.g., remote URLs) depending on tooling.", confidenceRationale: "Heuristic: processing can be safe with sandboxing and size limits.", recommendation: "Enforce size limits, strip metadata, use safe libraries, and consider sandboxing image processing workloads." }
};

export const F916_PDF_OR_DOC_PROCESSING_UNTRUSTED = {
    id: "F916_PDF_OR_DOC_PROCESSING_UNTRUSTED",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["pdf", "doc", "docx", "office", "convert", "parse"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)pdf\\b|docx\\b|libreoffice|soffice|pandoc|tika|pdfminer|poppler"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Parsers", shortLabel: "PDF/DOC parse", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Untrusted document processing added/modified", description: "Code processes PDFs or office documents.", risk: "Document parsers and converters are frequent sources of RCE/DoS vulnerabilities when handling untrusted files.", confidenceRationale: "Heuristic: risk depends on isolation/sandboxing and strict validation.", recommendation: "Sandbox document processing, enforce strict size/type limits, and keep parsing tools patched. Avoid executing converters in-process." }
};

export const F917_UPLOAD_EXEC_PERMISSION = {
    id: "F917_UPLOAD_EXEC_PERMISSION",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,sh,bash}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["chmod", "permission", "execute", "upload"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["\\bchmod\\s*\\+x\\b", "\\bchmod\\s+7[0-7]{2}\\b", "(?i)setExecutable\\("] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Execution", shortLabel: "Exec perms", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Executable permissions set on files (review upload paths)", description: "Code sets executable permissions, which is risky if applied to user-controlled files or upload directories.", risk: "If uploads become executable, attackers can gain code execution by uploading scripts/binaries.", confidenceRationale: "chmod +x / 7xx patterns are explicit; exploitability depends on what file is being chmod'd.", recommendation: "Never mark user uploads executable. Store uploads with restrictive permissions and outside executable/search paths." }
};

export const F918_S3_KEY_FROM_USER_FILENAME = {
    id: "F918_S3_KEY_FROM_USER_FILENAME",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["s3", "putObject", "upload", "Key", "bucket"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bKey\\s*[:=]\\s*.*\\b(filename|originalname|file\\.name)\\b", "(?i)putObject\\([^\\)]*\\bKey\\b[^\\)]*\\b(filename|originalname|file\\.name)\\b"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Cloud storage", shortLabel: "S3 key", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "S3 object key derived from user filename", description: "S3 upload code appears to use user-provided filenames for object keys.", risk: "User-controlled keys can enable overwrites, namespace pollution, path-like traversal behaviors, and awkward ACL/policy interactions.", confidenceRationale: "Heuristic: depends on whether keys are sanitized, randomized, and scoped per tenant.", recommendation: "Generate server-side object keys (UUID + tenant prefix). Store original filenames as metadata after sanitization." }
};

export const F919_PRESIGNED_UPLOAD_PERMISSIVE = {
    id: "F919_PRESIGNED_UPLOAD_PERMISSIVE",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["presign", "signedUrl", "postPolicy", "content-type", "conditions"], withinChars: 280 } },
    detection: { type: "REGEX", patterns: ["(?i)presign|signedUrl|createPresigned|generatePresigned", "(?i)content-type\\s*[:=]\\s*['\"]\\*\\/\\*['\"]"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Cloud uploads", shortLabel: "Presigned", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Presigned upload policy may be permissive", description: "Presigned URL/policy generation appears to allow broad content types or lacks restrictive conditions nearby.", risk: "Permissive presigned uploads can allow unexpected file types, oversized uploads, and abusive storage usage.", confidenceRationale: "Heuristic: policy constraints may be applied in helper functions not visible in diff.", recommendation: "Restrict presigned uploads with conditions: content-type allowlist, size limits, key prefixes, and short expirations." }
};

export const F920_DELETE_FILE_USER_PATH = {
    id: "F920_DELETE_FILE_USER_PATH",
    tier: "TIER_1", kind: "WARN", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["delete", "unlink", "remove", "rm", "file"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(unlink|remove|delete|rmSync|os\\.remove|File\\.delete)\\b[^\\n]{0,200}\\b(req\\.(params|query)|params\\[|request\\.|input\\()"] },
    presentation: { group: "File Uploads & Path Traversal", subgroup: "Deletion", shortLabel: "Delete user path", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "File deletion may use user-controlled path", description: "A delete/unlink operation appears to use a path derived from request/user input.", risk: "Path traversal in deletion flows can remove arbitrary files, causing data loss or enabling further compromise.", confidenceRationale: "Heuristic: safe implementations delete by server-side IDs with strict path scoping.", recommendation: "Delete files by immutable IDs mapped to server-side paths. Canonicalize paths and enforce base-directory constraints." }
};

export const WARN_FILES_RULES = [
    F901_SAVE_UPLOAD_USER_FILENAME, F902_UPLOAD_NO_CONTENT_TYPE_ALLOWLIST, F903_UPLOAD_NO_EXTENSION_ALLOWLIST, F904_UPLOAD_SIZE_LIMIT_MISSING, F905_UPLOAD_TO_WEB_ROOT, F906_PATH_JOIN_WITH_USER_INPUT, F907_DIRECTORY_TRAVERSAL_REGEX_ONLY, F908_SERVE_FILE_FROM_USER_PATH, F909_ARCHIVE_EXTRACT_PATH_TRAVERSAL, F910_ZIP_SLIP_PATTERNS, F911_TAR_EXTRACT_UNSAFE, F912_TEMPFILE_INSECURE_USAGE, F913_FILENAME_NOT_SANITIZED, F914_MULTIPART_PARSING_DEBUG, F915_IMAGE_PROCESSING_UNTRUSTED, F916_PDF_OR_DOC_PROCESSING_UNTRUSTED, F917_UPLOAD_EXEC_PERMISSION, F918_S3_KEY_FROM_USER_FILENAME, F919_PRESIGNED_UPLOAD_PERMISSIVE, F920_DELETE_FILE_USER_PATH
];
