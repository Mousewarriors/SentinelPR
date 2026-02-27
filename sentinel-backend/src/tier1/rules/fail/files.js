/**
 * File Uploads & Path Traversal FAIL rules
 */

export const PATH001_NODE_USER_INPUT_PATH = {
    id: "PATH001_NODE_USER_INPUT_PATH",
    tier: "TIER_1", kind: "FAIL", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["FILESYSTEM_SINK", "HAS_NEAR_SOURCE"], withinSameHunk: true }
    },
    explanation: {
        title: "Node.js user input used directly in filesystem path",
        description: "User input from req.query, req.body, or req.params is passed directly to an 'fs' module sink without visible sanitization.",
        risk: "Allows an attacker to read/modify/delete arbitrary files on the server (Local File Inclusion / Path Traversal).",
        confidenceRationale: "Triggers on same-line direct usage of request parameters in filesystem sinks.",
        recommendation: "Never use user input directly as a path. Sanitize paths using path.normalize(), or use an allowlist of permitted filenames."
    }
};

export const PATH002_PYTHON_USER_INPUT_OPEN = {
    id: "PATH002_PYTHON_USER_INPUT_OPEN",
    tier: "TIER_1", kind: "FAIL", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.py"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "open\\(.*request\\.(args|form|values)\\.get\\(",
            "open\\(.*request\\.args\\[",
            "open\\(.*request\\.form\\["
        ]
    },
    explanation: {
        title: "Python user input used in open()",
        description: "Flask/Django request data is passed directly to the open() function.",
        risk: "Potential path traversal vulnerability allowing access to arbitrary files.",
        confidenceRationale: "Triggers on same-line usage of request parameters in file open calls.",
        recommendation: "Validate and sanitize all user-provided paths. Use os.path.basename() or similar to restrict access to a single directory."
    }
};

export const PATH003_RUBY_USER_INPUT_FILE = {
    id: "PATH003_RUBY_USER_INPUT_FILE",
    tier: "TIER_1", kind: "FAIL", category: "File Uploads & Path Traversal", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.rb"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: { type: "REGEX", patterns: ["File\\.(read|open)\\(.*params\\["] },
    explanation: {
        title: "Ruby user input used in File.read/open",
        description: "Request parameters are passed directly to File.read or File.open.",
        risk: "Arbitrary file disclosure via path traversal.",
        confidenceRationale: "Same-line detection of params in file sink.",
        recommendation: "Restrict file access to a specific directory and sanitize the input filename."
    }
};

export const PATH004_PHP_USER_INPUT_IO = {
    id: "PATH004_PHP_USER_INPUT_IO",
    tier: "TIER_1", kind: "FAIL", category: "File Uploads & Path Traversal", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.php"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "file_get_contents\\(\\s*\\$_GET\\[",
            "fopen\\(\\s*\\$_GET\\[",
            "include\\(\\s*\\$_GET\\[",
            "require\\(\\s*\\$_GET\\["
        ]
    },
    explanation: {
        title: "PHP user input used in sensitive file sink",
        description: "GET data is passed directly to functions like file_get_contents, include, or require.",
        risk: "Enables Remote File Inclusion (RFI) or Local File Inclusion (LFI), allowing an attacker to execute arbitrary code or read sensitive files.",
        confidenceRationale: "Detects direct usage of $_GET in critical sinks.",
        recommendation: "Avoid using user input in file operations. Use an allowlist of permitted files or strictly sanitize the input."
    }
};

export const FAIL_FILES_RULES = [
    PATH001_NODE_USER_INPUT_PATH, PATH002_PYTHON_USER_INPUT_OPEN, PATH003_RUBY_USER_INPUT_FILE, PATH004_PHP_USER_INPUT_IO
];
