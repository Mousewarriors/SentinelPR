/**
 * Go-specific FAIL rules
 *
 * Philosophy: Covers Go idioms that don't map cleanly to generic patterns —
 * database/sql with fmt.Sprintf, path traversal via filepath.Join,
 * and template injection in html/template vs text/template misuse.
 */

// GO001: SQL injection via fmt.Sprintf in database/sql
export const GO001_SQL_SPRINTF_INJECTION = {
    id: "GO001_SQL_SPRINTF_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: {
        fileGlobs: ["**/*.go"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // db.Query/QueryRow/Exec(fmt.Sprintf(...)) — classic Go SQLi pattern
            "(?i)db\\.(Query|QueryRow|Exec|ExecContext|QueryContext)\\s*\\(\\s*fmt\\.Sprintf\\s*\\(",
            // Also catches named var assigned from fmt.Sprintf then used inline on same line
            "(?i)fmt\\.Sprintf\\s*\\(\\s*[\"'][^\"']*%[sdvq][^\"']*[\"'][^;]*db\\.(Query|QueryRow|Exec)\\s*\\(",
            // GORM Raw/Exec with Sprintf
            "(?i)\\.Raw\\s*\\(\\s*fmt\\.Sprintf\\s*\\(",
            "(?i)\\.Exec\\s*\\(\\s*fmt\\.Sprintf\\s*\\("
        ]
    },
    explanation: {
        title: "SQL injection via fmt.Sprintf in database call",
        description: "A database query is constructed using fmt.Sprintf with user-controlled values and passed directly to a SQL execution function.",
        risk: "fmt.Sprintf builds a raw SQL string with user input embedded — this is SQL injection. Attackers can manipulate query logic to extract or modify any data.",
        confidenceRationale: "fmt.Sprintf inside a database execution call is a deterministic Go SQLi pattern with no legitimate use case.",
        recommendation: "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = ?\", id) — never fmt.Sprintf for SQL construction."
    }
};

// GO002: Path traversal via filepath with user input
export const GO002_PATH_TRAVERSAL = {
    id: "GO002_PATH_TRAVERSAL",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.go"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // filepath.Join or os.Open with r.FormValue / r.URL.Query
            "(?i)filepath\\.(Join|Abs)\\s*\\([^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            "(?i)os\\.(Open|Create|ReadFile|WriteFile)\\s*\\([^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            // ioutil.ReadFile with user input
            "(?i)ioutil\\.ReadFile\\s*\\([^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            // http.ServeFile with unvalidated path
            "(?i)http\\.ServeFile\\s*\\(w\\s*,\\s*r\\s*,[^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\("
        ]
    },
    explanation: {
        title: "Path traversal via user input in Go file operation",
        description: "A file operation constructs or uses a path derived from user-supplied request values.",
        risk: "Attackers can supply paths containing ../ sequences to read sensitive files outside the intended directory.",
        confidenceRationale: "File API with r.FormValue/r.URL.Query on the same line is a direct path traversal pattern.",
        recommendation: "Use filepath.Clean() then verify the result starts with the expected base directory. Use filepath.Join(baseDir, filename) and always validate. Never pass raw user input to file APIs."
    }
};

// GO003: Go template injection (text/template instead of html/template with user data)
export const GO003_TEMPLATE_INJECTION = {
    id: "GO003_TEMPLATE_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.go"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // text/template.New(...).Parse(userInput) — no auto-escaping
            "(?i)text/template[^\\n]{0,200}template\\.New\\s*\\([^)]*\\)\\.Parse\\s*\\([^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            // template.Must(template.New(...).Parse(userInput))
            "(?i)template\\.Must\\s*\\(\\s*template\\.New\\s*\\([^)]*\\)\\.Parse\\s*\\([^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\("
        ]
    },
    explanation: {
        title: "Go text/template injection with user input",
        description: "A Go text/template (which does NOT auto-escape HTML) is parsed or executed with user-controlled template content.",
        risk: "Template injection via text/template allows XSS and potentially RCE via template actions like {{call}}.",
        confidenceRationale: "text/template.Parse() with request input is an unambiguous injection pattern.",
        recommendation: "Use html/template (which auto-escapes) instead of text/template for HTML output. Never parse user-controlled content as a template — only inject data into templates, not the templates themselves."
    }
};

export const FAIL_GO_RULES = [
    GO001_SQL_SPRINTF_INJECTION,
    GO002_PATH_TRAVERSAL,
    GO003_TEMPLATE_INJECTION
];
