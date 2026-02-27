/**
 * Tier 1 FAIL Rules: Injection
 *
 * Philosophy:
 * - Deterministic, high-precision detection of "slam dunk" injection vulnerabilities.
 * - Only analyzes added lines.
 * - Near-zero false positives.
 */

// SQL001: Template string interpolation passed directly into query execution
export const SQL001_TEMPLATE_TO_QUERY = {
    id: "SQL001_TEMPLATE_TO_QUERY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,jsx,ts,tsx,java,go,cs,rb,php,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Assignment-based detection (Proactive)
            "(?i)(db_query|sql_stmt|query_str|sql_query)\\s*[\\.\\w]*\\s*[:=]+\\s*[\"']?.*(\\$\\{|#\\{|\\{\\$|\\{\\{|%).*",
            // JS/TS: template literal interpolation in query call
            "(?i)\\.(query|execute|$queryRaw)\\s*\\(\\s*.*(\\$\\{|#\\{|\\{\\$|\\{\\{|%).*\\)",
            "(?i)knex\\.raw\\(\\s*.*(\\$\\{|#\\{|\\{\\$|\\{\\{|%).*\\)",
            "(?i)sequelize\\.query\\(\\s*.*(\\$\\{|#\\{|\\{\\$|\\{\\{|%).*\\)",
            "(?i)new\\s+require\\(['\"]sqlite3['\"]\\)\\.Database\\(\\s*(f['\"]|[`'\"].*(\\$\\{|#\\{|\\{\\$|\\{\\{|%|\\+)).*\\)",
            "(?i)\\.(query|execute)\\(\\s*.*\\+\\s*.*\\)",
            // Go: db.Query/Exec with fmt.Sprintf interpolation
            "(?i)db\\.(Query|QueryRow|Exec)\\s*\\(\\s*fmt\\.Sprintf\\(",
            "(?i)db\\.(Query|QueryRow|Exec)\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+",
            // Java: createNativeQuery or createQuery with string concat/format
            "(?i)\\bcreateNativeQuery\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+",
            "(?i)\\bcreateNativeQuery\\s*\\(\\s*String\\.format\\(",
            "(?i)\\bJdbcTemplate\\b.*\\.(query|update|execute)\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+",
            // C#: SqlCommand / SqliteCommand with string concat
            "(?i)new\\s+(Sql|Sqlite|Npgsql|MySql)Command\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+",
            "(?i)new\\s+(Sql|Sqlite|Npgsql|MySql)Command\\s*\\(\\s*\\$[\"']",
            // Ruby/Rails: interpolation in where/find_by_sql/execute
            "(?i)\\.(where|find_by_sql|execute|query)\\s*\\(\\s*[\"'][^\"']*#\\{.*\\}[^\"']*[\"']",
            // PHP: string interpolation or concat into mysql/mysqli/pdo query/execute
            "(?i)(mysql_query|mysqli_query|->query|->execute|->prepare|->exec)\\s*\\(\\s*[\"']?.*(\\$_(GET|POST|REQUEST|COOKIE|SESSION)|\\{\\$|\\$.*\\.).*[\"']?\\s*\\)",
            // Python: f-string, .format(), or % interpolation
            "(?i)\\.execute\\(\\s*(f['\"].*\\{.*\\}.*['\"]|['\"].*\\{.*\\}.*['\"]\\.format\\(|['\"].*%.*['\"]\\s*%)",
            "(?i)sqlite3\\.connect\\(\\s*.*(\\+|f['\"]|%).*\\)"
        ]
    },
    explanation: {
        title: "SQL query built with string interpolation or concatenation",
        description: "A SQL query string is constructed via template interpolation, string concatenation, or format strings, then passed into a query execution API.",
        risk: "Interpolating or concatenating user input into SQL enables SQL injection, allowing attackers to read, modify, or delete database data.",
        confidenceRationale: "Interpolation or concatenation inside a direct query execution call is a deterministic indicator of unsafe query construction.",
        recommendation: "Use parameterized queries or prepared statements in every language: ? placeholders (Go/Java/PHP), @param (C#), bind parameters (Rails ActiveRecord)."
    }
};

// SQL002: String concatenation passed directly into query execution
export const SQL002_CONCAT_TO_QUERY = {
    id: "SQL002_CONCAT_TO_QUERY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,java,go,cs,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Assignment-based detection (Proactive)
            "(?i)(db_query|sql_stmt|query_str|sql_query)\\s*[\\.\\w]*\\s*[:=]+\\s*([\"'][^\"']*[\"']\\s*\\+|[^\"']*\\+\\s*[\"'][^\"']*[\"']|.*\\.\\s*\\$_(GET|POST|REQUEST))",
            "(?i)\\.(query|execute)\\(\\s*([\"'][^\"']*[\"']\\s*\\+|[^\"']*\\+\\s*[\"'][^\"']*[\"'])\\s*",
            "(?i)knex\\.raw\\(\\s*([\"'][^\"']*[\"']\\s*\\+|[^\"']*\\+\\s*[\"'][^\"']*[\"'])\\s*",
            "(?i)sequelize\\.query\\(\\s*([\"'][^\"']*[\"']\\s*\\+|[^\"']*\\+\\s*[\"'][^\"']*[\"'])\\s*",
            "(?i)prisma\\.\\$queryRawUnsafe\\(\\s*([\"'][^\"']*[\"']\\s*\\+|[^\"']*\\+\\s*[\"'][^\"']*[\"'])\\s*",
            // PHP: string concat in PDO/mysqli
            "(?i)(\\$pdo->query|\\$db->query|\\$conn->query|mysqli_query)\\s*\\([^)]*\\.\\s*\\$_(GET|POST|REQUEST)",
            // Ruby: string concat in find/where/query/execute
            "(?i)(ActiveRecord::Base|\\w+)\\.(find_by_sql|where|query|execute)\\s*\\(\\s*([\"'][^\"']*[\"']\\s*\\+|[^\"']*\\+\\s*[\"'][^\"']*[\"'])\\s*",
            // Python: string concatenation in execute
            "(?i)\\.execute\\(\\s*([^)]*\\+\\s*['\"]|['\"].*['\"]\\s*\\+)",
        ]
    },
    explanation: {
        title: "SQL query built with string concatenation",
        description: "A SQL query is built via string concatenation and passed into a query execution API.",
        risk: "Concatenating values into SQL strings enables SQL injection, potentially allowing full database compromise.",
        confidenceRationale: "String concatenation inside a query execution call is a high-confidence indicator of unsafe query construction.",
        recommendation: "Use parameterized queries or prepared statements. Pass all user values as bind parameters."
    }
};

// SQL003: Explicit unsafe raw SQL APIs
export const SQL003_UNSAFE_RAW_SQL_API = {
    id: "SQL003_UNSAFE_RAW_SQL_API",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,java,go,cs,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // JS/TS unsafe API names
            "\\$queryRawUnsafe\\(",
            "prisma\\.\\$queryRawUnsafe\\(",
            "(?i)entityManager\\.query\\(\\s*[`\"'].*(\\$\\{|\\+).*[`\"']",
            // Java: nativeQuery + untrusted string
            "(?i)\\bcreateNativeQuery\\s*\\(",
            // Go: database/sql with string-built query
            "(?i)\\bdb\\.(Exec|Query|QueryRow)\\s*\\(\\s*\"[^\"]*\"\\s*\\+",
            // PHP: old mysql_* family (deprecated/unsafe by design)
            "(?i)\\bmysql_query\\s*\\(",
            // C#: ExecuteNonQuery/ExecuteReader on a string-built query
            "(?i)\\.(ExecuteNonQuery|ExecuteReader|ExecuteScalar)\\s*\\(\\)",
            // Python: sqlite3.connect with dynamic value (often misused)
            "(?i)sqlite3\\.connect\\(\\s*\\w+\\s*\\)"
        ]
    },
    explanation: {
        title: "Unsafe raw SQL API used",
        description: "An explicitly unsafe raw SQL execution API was introduced.",
        risk: "Unsafe raw query APIs can enable SQL injection when any part of the query includes attacker-controlled input.",
        confidenceRationale: "APIs labeled as unsafe are intended for unparameterized SQL and are high risk by design.",
        recommendation: "Use safe parameterized query APIs (prepared statements, ORM bind parameters) instead of raw string execution."
    }
};

// SQL004: Direct request input interpolated into query string
export const SQL004_REQ_INPUT_IN_QUERY = {
    id: "SQL004_REQ_INPUT_IN_QUERY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,java,go,cs,rb,php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // JS/TS: req.* in template literal or concat query
            "(?i)\\.(query|execute)\\(\\s*`.*\\$\\{req\\.(query|body|params)\\..*\\}.*`\\s*\\)",
            "(?i)\\.(query|execute)\\(\\s*([\"'][^\"']*[\"']\\s*\\+\\s*req\\.(query|body|params)\\.|req\\.(query|body|params)\\.\\w+\\s*\\+\\s*[\"'])",
            "(?i)sequelize\\.query\\(.*req\\.(query|body|params)\\..*\\$\\{",
            "(?i)sequelize\\.query\\(.*req\\.(query|body|params)\\..*\\+",
            "(?i)knex\\.raw\\(.*req\\.(query|body|params)\\..*\\$\\{",
            "(?i)knex\\.raw\\(.*req\\.(query|body|params)\\..*\\+",
            // Java/Spring: request.getParameter in query string
            "(?i)(createNativeQuery|createQuery|JdbcTemplate)\\b.{0,200}request\\.getParameter\\(",
            // Go: r.FormValue / r.URL.Query().Get in db call
            "(?i)db\\.(Query|QueryRow|Exec)\\s*\\(.*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            // C#: Request.QueryString / Request.Form in SqlCommand
            "(?i)(SqlCommand|SqliteCommand|NpgsqlCommand)\\b.{0,200}Request\\.(QueryString|Form)\\[",
            // Ruby/Rails: params in where/find_by_sql
            "(?i)\\.where\\s*\\(\\s*[\"'][^\"']*#\\{\\s*params\\[",
            "(?i)\\.find_by_sql\\s*\\(\\s*[\"'][^\"']*#\\{\\s*params\\[",
            // PHP: $_GET/$_POST/$_REQUEST in query call
            "(?i)(mysql_query|mysqli_query|->query|->prepare)\\s*\\([^)]*\\$_(GET|POST|REQUEST|COOKIE)"
        ]
    },
    explanation: {
        title: "Direct user input in SQL query",
        description: "User-supplied input is directly interpolated or concatenated into a SQL query across JavaScript, Java, Go, C#, Ruby, or PHP.",
        risk: "Directly including user input in SQL queries is the most common path to SQL injection — potentially leading to full database compromise.",
        confidenceRationale: "A user-input source and query execution sink on the same line is a near-certain indicator of SQL injection.",
        recommendation: "Use parameterized queries in every language. Pass all user values as bind parameters, never as part of the query string."
    }
};

// NOSQL001: User input used as MongoDB operator key
export const NOSQL001_OPERATOR_INJECTION = {
    id: "NOSQL001_OPERATOR_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)[\"']\\$where[\"']\\s*:\\s*(`.*\\$\\{.*\\}.*`|[\"'].*[\"']\\s*\\+|.*\\+\\s*[\"'].*[\"'])",
            "(?i)[\"']\\$regex[\"']\\s*:\\s*req\\.(query|body|params)\\.",
            "(?i)[\"']\\$expr[\"']\\s*:\\s*req\\.(query|body|params)\\."
        ]
    },
    explanation: {
        title: "Potential NoSQL injection via MongoDB operator",
        description: "A MongoDB query operator was constructed using untrusted input.",
        risk: "NoSQL operator injection can allow attackers to modify query logic, bypass filters, or extract unauthorized data.",
        confidenceRationale: "Using dangerous MongoDB operators ($where/$regex/$expr) directly with untrusted input is a deterministic high-risk pattern.",
        recommendation: "Avoid $where, strictly validate inputs used in $regex/$expr, and use safe query patterns with allowlists."
    }
};

// NOSQL002: Dynamic object key from request used in query filter
export const NOSQL002_DYNAMIC_FIELD_QUERY = {
    id: "NOSQL002_DYNAMIC_FIELD_QUERY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)(find|findOne|where)\\(\\s*\\{\\s*\\[\\s*req\\.(query|body|params)\\..*\\s*\\]\\s*:"
        ]
    },
    explanation: {
        title: "Dynamic query field controlled by request input",
        description: "A database query filter uses a field name controlled by request input.",
        risk: "Allowing attackers to choose query fields can bypass security controls or query sensitive fields unexpectedly.",
        confidenceRationale: "Computed property names derived from request input in query filters are a deterministic and high-risk pattern.",
        recommendation: "Use an allowlist of permitted fields and map user input to safe, predefined field names."
    }
};

// NOSQL003: JSON.parse(req.*) passed directly into find() / where()
export const NOSQL003_JSON_PARSE_IN_QUERY = {
    id: "NOSQL003_JSON_PARSE_IN_QUERY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\.(find|findOne|where)\\(\\s*JSON\\.parse\\(\\s*req\\.(body|query|params)\\..*\\)\\s*\\)"
        ]
    },
    explanation: {
        title: "JSON.parse of request input used as query object",
        description: "Request input is parsed as JSON and used directly as a query filter object.",
        risk: "Attackers can pass arbitrary query objects, including dangerous operators, enabling data exposure or bypass of application logic.",
        confidenceRationale: "Directly parsing user input into a query object is a highly dangerous and deterministic pattern.",
        recommendation: "Avoid parsing JSON from users directly into queries. Define explicit schemas and validate input fields individually."
    }
};

// CMD001: Direct request input in shell/command sinks
export const CMD001_UNSAFE_COMMAND_EXEC = {
    id: "CMD001_UNSAFE_COMMAND_EXEC",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Assignment-based detection (Proactive)
            "(?i)(cmd|command|sh_cmd|shell_cmd|args)\\s*[\\.\\w]*\\s*[:=]+\\s*[\"']?.*(\\$\\{|#\\{|\\{\\$|\\{\\{|%|\\+|env\\[|ENV\\[).*",
            // JS/Node.js: exec/spawn with req.*
            "(?i)\\b(exec|execSync|spawn|system|shell_exec|popen|subprocess\\.)\\b.*req\\.(query|params|body)\\.",
            "(?i)\\b(exec|execSync|spawn|system|shell_exec|popen|subprocess\\.)\\b\\(.*\\$\\{req\\.",
            "(?i)\\b(exec|execSync|spawn|system|shell_exec|popen|subprocess\\.)\\b\\(.*\\+\\s*req\\.",
            // Java: Runtime.exec or ProcessBuilder with request.getParameter
            "(?i)Runtime\\.getRuntime\\s*\\(\\s*\\)\\.exec\\s*\\([^)]*request\\.getParameter\\(",
            "(?i)new\\s+ProcessBuilder\\s*\\([^)]*request\\.getParameter\\(",
            // Go: exec.Command with shell -c and r.FormValue
            "(?i)exec\\.Command\\s*\\(\\s*[\"'](sh|bash|cmd|powershell)[\"']\\s*,\\s*[\"']-c[\"'][^)]*r\\.(FormValue|URL\\.Query\\(\\)\\.Get)\\(",
            // C#: Process.Start with Request input
            "(?i)Process\\.Start\\s*\\([^)]*Request\\.(QueryString|Form)\\[",
            "(?i)new\\s+ProcessStartInfo\\s*\\([^)]*Request\\.(QueryString|Form)\\[",
            // Ruby: system/exec/backtick with params
            "(?i)\\b(system|exec|popen)\\s*\\([^)]*params\\[:",
            "(?i)`[^`]*#\\{\\s*params\\[:",
            // PHP: exec/system/passthru/shell_exec with $_GET/$_POST
            "(?i)\\b(exec|system|passthru|shell_exec|popen)\\s*\\([^)]*\\$_(GET|POST|REQUEST|COOKIE)"
        ]
    },
    explanation: {
        title: "Direct user input in command execution",
        description: "User-supplied input is passed directly to a command execution sink across JavaScript, Java, Go, C#, Ruby, or PHP.",
        risk: "Allows Remote Code Execution (RCE). Attackers can execute arbitrary shell commands with the privileges of the application process.",
        confidenceRationale: "A user-input source and a shell execution sink on the same line is a near-certain indicator of command injection.",
        recommendation: "Never pass user input to shell commands. Use allowlisted argument arrays and avoid spawning shells. Prefer native libraries over shell commands."
    }
};

// XML001: Unsafe XML parsing (XXE) with potential user input
export const XML001_XXE_VULNERABILITY = {
    id: "XML001_XXE_VULNERABILITY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["XML_NOENT_TRUE", "XML_USER_SINK"],
            withinSameHunk: true,
            withinLines: 15
        }
    },
    explanation: {
        title: "Unsafe XML parsing (XXE)",
        description: "XML parser is configured to enable entity expansion (noent: true) while processing potential user input.",
        risk: "Enables XML External Entity (XXE) attacks, allowing attackers to read local files, probe internal networks, or cause DoS.",
        confidenceRationale: "Explicitly enabling 'noent' (no entity expansion disabled) in a parser processing request data is a high-risk pattern.",
        recommendation: "Disable external entity expansion in your XML parser configuration (e.g., set noent: false or similar library-specific flags)."
    }
};

// RCE001: eval / new Function / vm.runInContext with direct request input
export const RCE001_EVAL_USER_INPUT = {
    id: "RCE001_EVAL_USER_INPUT",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // JS/TS: eval/new Function/vm.run with req.*
            "(?i)\\beval\\s*\\(.*req\\s*\\.\\s*(query|params|body)\\.",
            "(?i)\\bnew\\s+Function\\s*\\(.*req\\s*\\.\\s*(query|params|body)\\.",
            "(?i)\\bvm\\s*\\.\\s*run(InThisContext|InNewContext|Script)\\s*\\(.*req\\s*\\.\\s*(query|params|body)\\.",
            "(?i)\\beval\\s*\\(\\s*(`[^`]*\\$\\{\\s*req\\.|[^\"')]*req\\.(query|params|body))",
            // Python: eval/exec with request.*
            "(?i)\\b(eval|exec)\\s*\\(\\s*request\\.(args|form|json|data|values|get_json)",
            // Ruby: eval with params
            "(?i)\\beval\\s*\\([^)]*params\\[:",
            "(?i)\\binstance_eval\\s*\\([^)]*params\\[:",
            // PHP: eval with $_GET/$_POST/$_REQUEST
            "(?i)\\beval\\s*\\([^)]*\\$_(GET|POST|REQUEST|COOKIE)",
            // Java: ScriptEngine.eval with request.getParameter
            "(?i)\\bScriptEngine\\b.{0,200}\\.eval\\s*\\([^)]*request\\.getParameter\\(",
            "(?i)\\b(Compilable|Invocable)\\b.{0,200}\\.eval\\s*\\([^)]*request\\.getParameter\\("
        ]
    },
    explanation: {
        title: "eval() or dynamic code execution with user input",
        description: "User-supplied input is passed directly to eval(), new Function(), ScriptEngine.eval(), or equivalent dynamic code execution APIs.",
        risk: "Allows Remote Code Execution (RCE) in the server process with full application privileges — one of the most severe vulnerability classes.",
        confidenceRationale: "Dynamic code execution API + user-input source on the same line is one of the most deterministic RCE indicators in static analysis.",
        recommendation: "Never pass user input to eval() or equivalent APIs in any language. Use JSON.parse for data, allowlisted expression evaluators, or template engines with auto-escaping."
    }
};

// SSTI001: Server-Side Template Injection
export const SSTI001_TEMPLATE_INJECTION = {
    id: "SSTI001_TEMPLATE_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Python: Jinja2/Mako/Mottle render_template_string with request input
            "(?i)\\brender_template_string\\s*\\([^)]*request\\.(args|form|values|json|data)",
            // Node/JS: ejs/pug/handlebars render/compile with req input
            "(?i)\\.(render|compile|renderString|renderFile)\\s*\\([^,]+,\\s*\\{[^}]*req\\.(query|body|params)",
            "(?i)Handlebars\\.compile\\s*\\([^)]*req\\.(query|body|params)",
            // Ruby/Rails: ERB/Liquid.parse with params
            "(?i)ERB\\.new\\s*\\([^)]*params\\[:",
            "(?i)Liquid::Template\\.parse\\s*\\([^)]*params\\[:",
            // Java: Freemarker/Velocity evaluate/getTemplate with request input
            "(?i)\\.process\\s*\\([^,]+,[^)]*request\\.getParameter",
            "(?i)Velocity\\.evaluate\\s*\\([^)]*request\\.getParameter"
        ]
    },
    explanation: {
        title: "Server-Side Template Injection (SSTI)",
        description: "User-controlled input is passed directly into a template rendering engine.",
        risk: "SSTI allows attackers to execute arbitrary code on the server (RCE) by injecting template directives (e.g., {{7*7}}, {{self.__init__.__globals__}}).",
        confidenceRationale: "Directly passing request data into template parsing or rendering functions is a high-confidence indicator of SSTI.",
        recommendation: "Never allow users to provide their own templates. Use templates defined in the filesystem and only pass user input as data variables within the template context."
    }
};

// LDAP001: LDAP Injection
export const LDAP001_LDAP_INJECTION = {
    id: "LDAP001_LDAP_INJECTION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{js,jsx,ts,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Generic LDAP search/bind with concatenation
            "(?i)\\.(search|bind|find|get)\\s*\\([^,]*['\"][^'\"]*=[^'\"]*['\"]\\s*\\+",
            "(?i)\\.(search|bind|find|get)\\s*\\([^,]*[`\"'].*\\$\\{.*\\}.*[`\"']",
            "(?i)\\.(search|bind|find|get)\\s*\\(.*request\\.(getParameter|args|form|query|body)",
            "(?i)\\.(search|bind|find|get)\\s*\\(.*params\\[:"
        ]
    },
    explanation: {
        title: "LDAP Injection",
        description: "User input is used to construct an LDAP filter or DN without proper escaping.",
        risk: "LDAP injection allows attackers to bypass authentication, extract unauthorized user data, or modify LDAP directory content.",
        confidenceRationale: "String-built LDAP filters using request input are a deterministic injection pattern.",
        recommendation: "Use parameterized LDAP queries or properly escape user input using an LDAP escaping library before including it in a filter or DN."
    }
};

// ZIP001: Zip Slip (Archive Path Traversal)
export const ZIP001_ZIP_SLIP = {
    id: "ZIP001_ZIP_SLIP",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{java,go,js,ts,py,rb}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: false, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Java: zipEntry.getName() followed by file write (heuristic based on proximity)
            "(?i)\\.getName\\s*\\(\\s*\\).{0,100}new\\s+File\\s*\\(",
            "(?i)\\.getName\\s*\\(\\s*\\).{0,100}Paths\\.get",
            // Node/JS: unzipper/adm-zip entry name used in file operations
            "(?i)\\.entryName.{0,50}fs\\.write",
            "(?i)\\.path.{0,50}fs\\.createWriteStream",
            // Go: archive/zip File.Name in os.OpenFile
            "(?i)\\.Name.{0,50}os\\.(Open|Create|OpenFile)"
        ]
    },
    explanation: {
        title: "Zip Slip (Archive Path Traversal)",
        description: "An archive entry's filename is used directly in a file operation without validating that it remains within the target directory.",
        risk: "Attackers can create malicious archives with filenames like '../../etc/passwd' to overwrite sensitive files or execute code via path traversal.",
        confidenceRationale: "Extracting archive entries and writing them to the filesystem using their internal names without explicit validation is a documented high-risk pattern.",
        recommendation: "Always validate that the final path of an extracted file is within the intended base directory using canonical paths and prefix matching."
    }
};

// DES001: Unsafe Deserialization
export const DES001_UNSAFE_DESERIALIZATION = {
    id: "DES001_UNSAFE_DESERIALIZATION",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/*.{py,rb,php,js,ts}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Python: pickle.loads
            "(?i)pickle\\.loads\\s*\\(",
            "(?i)yaml\\.unsafe_load\\s*\\(",
            // Ruby: Marshal.load
            "(?i)Marshal\\.load\\s*\\(",
            // PHP: unserialize
            "(?i)\\bunserialize\\s*\\(\\s*\\$_(GET|POST|REQUEST|COOKIE|SERVER)",
            // Node/JS: serialize-javascript / node-serialize
            "(?i)unserialize\\s*\\(\\s*req\\.(query|body|params)"
        ]
    },
    explanation: {
        title: "Unsafe Deserialization",
        description: "Untrusted data is passed to a deserialization engine that supports executable objects.",
        risk: "Allows Remote Code Execution (RCE). Attackers can craft malicious serialized streams to instantiate arbitrary classes and execute code.",
        confidenceRationale: "These APIs are inherently dangerous when used with untrusted input.",
        recommendation: "Avoid deserializing data from untrusted sources. Use safe, data-only formats like JSON or Protocol Buffers. If deserialization is required, use strict allowlisting of classes."
    }
};

export const FAIL_INJECTION_RULES = [
    SQL001_TEMPLATE_TO_QUERY,
    SQL002_CONCAT_TO_QUERY,
    SQL003_UNSAFE_RAW_SQL_API,
    SQL004_REQ_INPUT_IN_QUERY,
    NOSQL001_OPERATOR_INJECTION,
    NOSQL002_DYNAMIC_FIELD_QUERY,
    NOSQL003_JSON_PARSE_IN_QUERY,
    CMD001_UNSAFE_COMMAND_EXEC,
    XML001_XXE_VULNERABILITY,
    RCE001_EVAL_USER_INPUT,
    SSTI001_TEMPLATE_INJECTION,
    LDAP001_LDAP_INJECTION,
    ZIP001_ZIP_SLIP,
    DES001_UNSAFE_DESERIALIZATION
];
