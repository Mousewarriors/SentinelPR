/**
 * C# / .NET-specific FAIL rules
 *
 * Philosophy: Covers .NET idioms that don't map cleanly to generic patterns —
 * SqlCommand string building, ViewState/Razor injection, path traversal,
 * and XML external entity exposure in .NET XML parsers.
 */

// DOTNET001: SQL injection via SqlCommand string concatenation
export const DOTNET001_SQL_STRING_CONCAT = {
    id: "DOTNET001_SQL_STRING_CONCAT",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "CRITICAL",
    appliesTo: {
        fileGlobs: ["**/*.{cs,vb,aspx,cshtml}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // new SqlCommand("SELECT... " + Request.QueryString["..."])
            "(?i)new\\s+(Sql|Sqlite|Npgsql|MySql|OleDb)Command\\s*\\([^)]*Request\\.(QueryString|Form|Params)\\[",
            // string.Format("SELECT... {0}", Request.QueryString["..."])
            "(?i)string\\.Format\\s*\\(\\s*[\"'][^\"']*SELECT[^\"']*[\"'][^)]*Request\\.(QueryString|Form|Params)\\[",
            // SqlCommand with C# string interpolation from Request
            "(?i)new\\s+(Sql|Sqlite|Npgsql|MySql|OleDb)Command\\s*\\(\\s*\\$[\"'][^\"']*Request\\.(QueryString|Form|Params)",
            // EntityFramework raw SQL with user input
            "(?i)\\.FromSqlRaw\\s*\\([^)]*Request\\.(QueryString|Form)\\[",
            "(?i)\\.ExecuteSqlRaw\\s*\\([^)]*Request\\.(QueryString|Form)\\["
        ]
    },
    explanation: {
        title: "SQL injection via SqlCommand with request input",
        description: "A .NET SQL command is built by concatenating or interpolating values from Request.QueryString, Request.Form, or Request.Params.",
        risk: "SQL injection allows attackers to read, modify, or delete any database data, bypass authentication, or escalate privileges.",
        confidenceRationale: "SqlCommand construction with Request input on the same line is a deterministic SQLi indicator in .NET.",
        recommendation: "Use SqlCommand with parameterized queries: cmd.Parameters.AddWithValue(\"@id\", Request.QueryString[\"id\"]). Never concatenate or interpolate Request values into SQL."
    }
};

// DOTNET002: Path traversal via Request input in file operations
export const DOTNET002_PATH_TRAVERSAL = {
    id: "DOTNET002_PATH_TRAVERSAL",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.{cs,vb,aspx}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // System.IO.File or Path operations with Request input
            "(?i)(File\\.(ReadAll|WriteAll|Open|Create)|Path\\.(Combine|GetFullPath))\\b[^;]*Request\\.(QueryString|Form|Params)\\[",
            // new FileStream with Request input
            "(?i)new\\s+FileStream\\s*\\([^)]*Request\\.(QueryString|Form|Params)\\[",
            // Server.MapPath with Request input
            "(?i)Server\\.MapPath\\s*\\([^)]*Request\\.(QueryString|Form|Params)\\["
        ]
    },
    explanation: {
        title: "Path traversal via Request input in .NET file operation",
        description: "A .NET file operation constructs a file path using Request.QueryString, Request.Form, or Request.Params.",
        risk: "Attackers can supply ..\\..\\windows\\system32\\config or similar sequences to access sensitive files outside the web root.",
        confidenceRationale: "File API with Request input on the same line is a direct path traversal indicator.",
        recommendation: "Sanitize file paths using Path.GetFullPath() and verify the result starts with the expected base directory. Never pass Request values directly to file APIs."
    }
};

// DOTNET003: XXE in .NET XML parsers
export const DOTNET003_XXE_XML_PARSER = {
    id: "DOTNET003_XXE_XML_PARSER",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.{cs,vb}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // XmlDocument without XmlResolver = null
            "(?i)new\\s+XmlDocument\\s*\\(\\s*\\)",
            // XmlReader.Create without XmlReaderSettings.DtdProcessing = Prohibit
            "(?i)XmlReaderSettings\\b[^;]{0,300}DtdProcessing\\s*=\\s*DtdProcessing\\.(Parse|Default)\\b",
            // XDocument or XElement loaded without safe settings
            "(?i)XDocument\\.Load\\s*\\(",
            // DataSet/DataTable deserialization from XML (classic .NET XXE/RCE vector)
            "(?i)\\b(DataSet|DataTable)\\b[^;]{0,200}\\.ReadXml\\s*\\("
        ]
    },
    explanation: {
        title: "XXE-vulnerable .NET XML parser configuration",
        description: "A .NET XML parser (XmlDocument, XmlReader, XDocument, DataSet.ReadXml) is used without explicitly disabling external entity processing.",
        risk: "XXE (XML External Entity) injection can expose server files, internal network resources, or cloud metadata endpoints. DataSet.ReadXml() from untrusted data is a critical RCE/XXE vector in older .NET versions.",
        confidenceRationale: "These APIs are vulnerable by default in .NET Framework; .NET Core mitigated some but not all cases.",
        recommendation: "Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit and XmlDocument.XmlResolver = null. Prefer XDocument with XmlReader configured safely. Avoid DataSet.ReadXml() with untrusted data."
    }
};

// DOTNET004: Razor/ASPX HTML raw output of request data
export const DOTNET004_RAW_HTML_OUTPUT = {
    id: "DOTNET004_RAW_HTML_OUTPUT",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Injection",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.{cshtml,aspx,ascx,vbhtml}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // @Html.Raw(Request.*) in Razor views
            "(?i)@Html\\.Raw\\s*\\([^)]*Request\\.(QueryString|Form|Params)\\[",
            // <%=Request["param"]%> in ASPX (unencoded output)
            "(?i)<%=\\s*Request\\s*[\\.\\[]",
            // MvcHtmlString.Create from Request
            "(?i)MvcHtmlString\\.Create\\s*\\([^)]*Request\\.(QueryString|Form)\\["
        ]
    },
    explanation: {
        title: "Unencoded request data rendered in Razor/ASPX view",
        description: "Request-derived input is rendered raw into an HTML view using Html.Raw(), <%=...%>, or MvcHtmlString.Create().",
        risk: "XSS (Cross-Site Scripting) — attackers inject scripts that steal session cookies, redirect users, or perform browser-side actions on their behalf.",
        confidenceRationale: "Html.Raw() and <%=...%> explicitly bypass the framework's HTML encoding — passing Request data here is unambiguous XSS.",
        recommendation: "Use @Model.Property (auto-encoded in Razor) or Html.Encode() instead of Html.Raw(). Never pass Request data directly to raw output methods."
    }
};

export const FAIL_DOTNET_RULES = [
    DOTNET001_SQL_STRING_CONCAT,
    DOTNET002_PATH_TRAVERSAL,
    DOTNET003_XXE_XML_PARSER,
    DOTNET004_RAW_HTML_OUTPUT
];
