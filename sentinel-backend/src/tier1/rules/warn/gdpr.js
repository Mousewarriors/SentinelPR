// Data Privacy & GDPR WARN pack (P1301–P1322)
// - Single consolidated file per guidelines (no subfolders).
// - Diff-first (ADDED_ONLY).
// - Low-noise: focuses on explicit PII schema fields, “wholesale user object” API responses,
//   and explicit Postgres RLS disable signals.

/* -------------------------
 * Schema / Migration PII rules
 * ------------------------- */

export const P1301_SCHEMA_SSN_COLUMN = {
    id: "P1301_SCHEMA_SSN_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "model ", "schema", "migration"], withinChars: 480 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(ssn|social[_-]?security)\\b\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)",
            "(?i)\\b(ssn|social[_-]?security)\\b\\s*[:=]",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "SSN field", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Schema introduces SSN-like field",
        description: "A schema/migration appears to add an SSN/social security number field.",
        risk: "Highly sensitive identifiers increase breach impact and regulatory exposure. Storing them in cleartext can be especially risky.",
        confidenceRationale: "Field names like `ssn`/`social_security` are explicit and strongly indicative of sensitive PII.",
        recommendation: "Avoid storing SSNs unless required. If required, apply strict access controls, encryption/tokenization, and minimize retention.",
    },
};

export const P1302_SCHEMA_NATIONAL_ID_TAX_ID_COLUMN = {
    id: "P1302_SCHEMA_NATIONAL_ID_TAX_ID_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "model ", "migration"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(national[_-]?id|tax[_-]?id|tin|ein|vat[_-]?id)\\b\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)",
            "(?i)\\b(national[_-]?id|tax[_-]?id|tin|ein|vat[_-]?id)\\b\\s*[:=]",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "Gov ID field", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Schema introduces government/tax identifier field",
        description: "A schema/migration appears to add a national ID / tax ID / VAT ID field.",
        risk: "Government identifiers are high-impact PII. Breach exposure can be severe and often triggers strict reporting obligations.",
        confidenceRationale: "Field names (national_id, tax_id, tin, ein, vat_id) are explicit indicators.",
        recommendation: "Store only if required, apply encryption/tokenization, restrict access, and document retention and lawful basis.",
    },
};

export const P1303_SCHEMA_PASSPORT_OR_LICENSE_COLUMN = {
    id: "P1303_SCHEMA_PASSPORT_OR_LICENSE_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "model ", "migration"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(passport|driver[_-]?license|driving[_-]?license|license[_-]?number)\\b\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)",
            "(?i)\\b(passport|driver[_-]?license|driving[_-]?license|license[_-]?number)\\b\\s*[:=]",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "Passport/license", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Schema introduces passport/license identifier field",
        description: "A schema/migration appears to add a passport or driver’s license identifier field.",
        risk: "These identifiers can enable identity fraud and materially increase breach severity and regulatory impact.",
        confidenceRationale: "Field names are explicit and strongly indicative of sensitive identity data.",
        recommendation: "Avoid collecting/storing unless necessary. If required, encrypt/tokenize, restrict access, and minimize retention.",
    },
};

export const P1304_SCHEMA_CARD_NUMBER_OR_CVV_COLUMN = {
    id: "P1304_SCHEMA_CARD_NUMBER_OR_CVV_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "CRITICAL",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "payment", "card", "billing", "migration"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(card[_-]?number|cc[_-]?number|pan|cvv|cvc)\\b\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)",
            "(?i)\\b(card[_-]?number|cc[_-]?number|pan|cvv|cvc)\\b\\s*[:=]",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "Card data", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Schema introduces card number/CVV-like field",
        description: "A schema/migration appears to add payment card number (PAN) or CVV/CVC-like fields.",
        risk: "Storing card numbers/CVV can create major compliance obligations and severe breach impact. CVV storage is generally prohibited under PCI DSS.",
        confidenceRationale: "Field names (card_number/pan/cvv/cvc) are explicit and high-signal.",
        recommendation: "Do not store CVV. Prefer tokenized payment providers. If storing PAN is unavoidable, follow PCI DSS and use tokenization/encryption and strict access controls.",
    },
};

export const P1305_SCHEMA_DOB_BIRTHDATE_COLUMN = {
    id: "P1305_SCHEMA_DOB_BIRTHDATE_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "MEDIUM",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "model ", "migration"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(dob|birthdate|date[_-]?of[_-]?birth)\\b\\s*[:\\s]+(date|datetime|timestamp|varchar|text|string|\\w+)",
            "(?i)\\b(dob|birthdate|date[_-]?of[_-]?birth)\\b\\s*[:=]",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "DOB field", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Schema introduces date-of-birth field",
        description: "A schema/migration appears to add a DOB/birthdate field.",
        risk: "DOB is sensitive PII and increases identity risk and privacy obligations, especially when combined with other identifiers.",
        confidenceRationale: "Field names (dob/birthdate/date_of_birth) are explicit and reliably detectable.",
        recommendation: "Collect/store only if necessary. Apply access controls, minimize retention, and consider partial storage (e.g., year only) if sufficient.",
    },
};

export const P1306_SCHEMA_PHONE_COLUMN = {
    id: "P1306_SCHEMA_PHONE_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "LOW",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "model ", "migration"], withinChars: 520 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(phone|phone_number|mobile|msisdn)\\b\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)", "(?i)\\b(phone|phone_number|mobile|msisdn)\\b\\s*[:=]"], },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "Phone field", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Schema introduces phone number field",
        description: "A schema/migration appears to add a phone/mobile field.",
        risk: "Phone numbers are personal data and can increase account takeover risk (SIM swap/social engineering) if exposed.",
        confidenceRationale: "Phone field names are explicit and deterministic.",
        recommendation: "Store only when needed, restrict access, and consider hashing/indexing strategies if used only for lookup.",
    },
};

export const P1307_SCHEMA_ADDRESS_COLUMN = {
    id: "P1307_SCHEMA_ADDRESS_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "LOW",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "address", "migration"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(address1|address2|street|postal[_-]?code|zip|city|state|province|country)\\b\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)",
            "(?i)\\b(address1|address2|street|postal[_-]?code|zip|city|state|province|country)\\b\\s*[:=]",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "Address PII", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: {
        title: "Schema introduces address-like personal data fields",
        description: "A schema/migration appears to add address-related personal data fields (street/city/postal code/etc.).",
        risk: "Address data increases privacy obligations and can materially increase harm in a breach when combined with identity attributes.",
        confidenceRationale: "Field names are indicative but can be used in non-PII contexts; kept conservative.",
        recommendation: "Collect only what’s necessary, restrict access, and ensure retention and export/deletion paths are implemented.",
    },
};

export const P1308_SCHEMA_EMAIL_COLUMN = {
    id: "P1308_SCHEMA_EMAIL_COLUMN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "LOW",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "model ", "migration"], withinChars: 520 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bemail\\b\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)", "(?i)\\bemail\\b\\s*[:=]"] },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "Email field", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: {
        title: "Schema introduces email field",
        description: "A schema/migration appears to add an email field.",
        risk: "Email addresses are personal data and are frequently targeted for phishing and account takeover.",
        confidenceRationale: "Field name is explicit but common; kept low severity and often hidden to reduce noise.",
        recommendation: "Restrict access to user identity tables, and avoid exposing emails unnecessarily in APIs and logs.",
    },
};

export const P1309_SCHEMA_PASSWORD_FIELD_NOT_HASH = {
    id: "P1309_SCHEMA_PASSWORD_FIELD_NOT_HASH",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "CRITICAL",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,prisma,rb,py,php,java,go,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["create table", "alter table", "add column", "model ", "migration", "users"], withinChars: 620 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\bpassword\\b(?![_-]?(hash|digest|encrypted))\\s*[:\\s]+(varchar|text|string|char|citext|character varying|\\w+)",
            "(?i)\\bpassword\\b(?![_-]?(hash|digest|encrypted))\\s*[:=]",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Schemas", shortLabel: "Password field", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Schema introduces a password field that does not look hashed",
        description: "A schema/migration appears to add a `password` column without hash/digest/encrypted naming.",
        risk: "Storing passwords in cleartext (or reversible form) is catastrophic and creates extreme breach impact.",
        confidenceRationale: "`password` as a stored field name (without hash/digest indicators) is a strong signal and rarely legitimate.",
        recommendation: "Store only password hashes (strong adaptive hashing) and never store raw passwords. Review authentication storage design immediately.",
    },
};

/* -------------------------
 * API response “wholesale object” rules
 * ------------------------- */

export const P1310_EXPRESS_RES_JSON_USER_OBJECT = {
    id: "P1310_EXPRESS_RES_JSON_USER_OBJECT",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["res.json", "res.send", "user", "users"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["\\bres\\.(json|send)\\(\\s*(user|users|currentUser)\\s*\\)"] },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "Return user object", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "API response returns user object directly",
        description: "Code returns a `user`/`users` object via `res.json`/`res.send` without obvious field filtering.",
        risk: "Returning whole user objects can leak sensitive fields (password hashes, tokens, email, phone, internal flags) to clients.",
        confidenceRationale: "This is a common footgun; field filtering may exist but is not obvious at the call site (hence WARN).",
        recommendation: "Return an explicit allowlist DTO/serializer (e.g., id/name) and exclude secrets (password hashes, reset tokens, internal roles).",
    },
};

export const P1311_EXPRESS_SPREAD_USER_OBJECT = {
    id: "P1311_EXPRESS_SPREAD_USER_OBJECT",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["res.json", "user", "..."], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["\\bres\\.json\\(\\s*\\{\\s*\\.\\.\\.(user|currentUser)\\b"] },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "Spread user", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "API response spreads user object into JSON",
        description: "Code returns `{ ...user }` (or similar) which can include unintended sensitive fields.",
        risk: "Object spreading can accidentally expose password hashes, tokens, internal flags, and PII.",
        confidenceRationale: "Spreading a user object is explicit and commonly leads to accidental data leaks.",
        recommendation: "Create an explicit response object with allowlisted fields only; avoid spreading ORM entities into responses.",
    },
};

export const P1312_RAILS_RENDER_JSON_USER = {
    id: "P1312_RAILS_RENDER_JSON_USER",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{rb}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["render", "json", "@user", "User"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\brender\\s+json:\\s*(@user|@users|user|users)\\b"] },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "render json user", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Rails controller renders user model as JSON",
        description: "Controller renders a User object/collection directly as JSON without an obvious serializer/allowlist.",
        risk: "Default JSON rendering can include sensitive columns depending on serialization configuration (password digests, tokens, email).",
        confidenceRationale: "Direct render is explicit; whether sensitive fields are included depends on serializers (hence WARN).",
        recommendation: "Use explicit serializers (ActiveModel::Serializer/Blueprinter/Jbuilder) with allowlisted fields for user responses.",
    },
};

export const P1313_DJANGO_SERIALIZER_FIELDS_ALL = {
    id: "P1313_DJANGO_SERIALIZER_FIELDS_ALL",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["ModelSerializer", "fields", "User", "serializer"], withinChars: 320 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bfields\\s*=\\s*['\\\"]__all__['\\\"]"] },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "fields=__all__", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Django serializer exposes all fields (fields = '__all__')",
        description: "A DRF ModelSerializer sets `fields = '__all__'`.",
        risk: "This can expose sensitive user fields by default (password hash, tokens, internal flags), especially as models evolve.",
        confidenceRationale: "The `__all__` literal is explicit and a known source of accidental overexposure.",
        recommendation: "Use an explicit allowlist of fields for API serializers and add tests to prevent regression exposures.",
    },
};

export const P1314_PYTHON_RETURN_USER_DICT = {
    id: "P1314_PYTHON_RETURN_USER_DICT",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["return", "user", "__dict__", "dict(", "jsonify"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\breturn\\s+(user\\.__dict__|dict\\(user\\)|jsonify\\(user\\)|jsonify\\(user\\.__dict__\\))"] },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "Return user dict", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "API response returns user object dictionary directly",
        description: "Code returns a user’s `__dict__` or similar direct dict conversion.",
        risk: "Direct dict conversion often includes internal fields and sensitive attributes not intended for clients.",
        confidenceRationale: "The patterns are explicit; whether sensitive fields exist depends on the model.",
        recommendation: "Use explicit response schemas/DTOs and filter out secrets and internal fields before returning JSON.",
    },
};

export const P1315_GRAPHQL_SCHEMA_PASSWORD_FIELD = {
    id: "P1315_GRAPHQL_SCHEMA_PASSWORD_FIELD",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "CRITICAL",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{graphql,gql,ts,js}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["type User", "GraphQLObjectType", "User", "fields"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\btype\\s+User\\b[\\s\\S]{0,420}\\b(password|passwordHash|password_digest|hashedPassword)\\b\\s*:",
            "(?i)\\bpassword(Hash|_digest|_digest)?\\b\\s*:\\s*\\w+\\s*(#.*)?$",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "GraphQL password field", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "GraphQL schema exposes password/password-hash field",
        description: "GraphQL schema appears to include password or password-hash fields on a user type.",
        risk: "Exposing password hashes to clients is a severe data leak and increases offline cracking risk.",
        confidenceRationale: "Field names are explicit in schema and strongly indicative of sensitive credential material.",
        recommendation: "Remove password/password-hash fields from GraphQL types. Expose only non-sensitive user profile fields via allowlists.",
    },
};

export const P1316_SELECT_STAR_USERS_IN_HANDLER = {
    id: "P1316_SELECT_STAR_USERS_IN_HANDLER",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "MEDIUM",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{sql,js,ts,py,rb,php,java,go}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["SELECT", "FROM users", "return", "res.json", "render json", "jsonify"], withinChars: 520 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bselect\\s+\\*\\s+from\\s+users\\b"] },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "SELECT * users", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Query selects all columns from users",
        description: "Code introduces `SELECT * FROM users` which commonly includes sensitive columns.",
        risk: "Selecting all columns increases the chance of leaking password hashes, tokens, internal flags, and PII to the application layer and responses.",
        confidenceRationale: "The SQL pattern is explicit; whether the result is returned to clients depends on the handler.",
        recommendation: "Select explicit allowlisted columns for user queries and separate internal columns from public profile data.",
    },
};

export const P1317_PRISMA_FIND_WITHOUT_SELECT_AND_RETURN = {
    id: "P1317_PRISMA_FIND_WITHOUT_SELECT_AND_RETURN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "MEDIUM",
    defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["prisma.", "findUnique", "findFirst", "findMany", "res.json", "return"], withinChars: 520 } },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["PRISMA_USER_QUERY_PRESENT", "NO_SELECT_CLAUSE_PRESENT_NEARBY", "RESPONSE_RETURNS_RESULT_PRESENT"], withinSameHunk: true, withinLines: 220 },
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "Prisma return model", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: {
        title: "Prisma user query returned without explicit select allowlist",
        description: "A Prisma user query appears returned in a response without an explicit `select` allowlist.",
        risk: "ORM entities can include sensitive fields that change over time; returning them directly risks accidental data exposure.",
        confidenceRationale: "Heuristic: Prisma may exclude some fields in application logic; emit only when analyzer sees query + response coupling.",
        recommendation: "Use explicit `select` for public user responses and map to a DTO/serializer before returning.",
    },
};

export const P1318_SEQUELIZE_FIND_WITHOUT_ATTRIBUTES_AND_RETURN = {
    id: "P1318_SEQUELIZE_FIND_WITHOUT_ATTRIBUTES_AND_RETURN",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "MEDIUM",
    defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["User.find", "findOne", "findByPk", "res.json", "return"], withinChars: 520 } },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["SEQUELIZE_USER_QUERY_PRESENT", "NO_ATTRIBUTES_ALLOWLIST_PRESENT_NEARBY", "RESPONSE_RETURNS_RESULT_PRESENT"], withinSameHunk: true, withinLines: 220 },
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "Sequelize return model", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: {
        title: "Sequelize user query returned without attributes allowlist",
        description: "A Sequelize query for a user appears returned without an explicit `attributes` allowlist.",
        risk: "Returning ORM models directly can leak password hashes, tokens, internal flags, and PII as schemas evolve.",
        confidenceRationale: "Heuristic: emit only when analyzer sees query + response coupling in the same hunk.",
        recommendation: "Use `attributes` allowlists (or serializers) and map responses to explicit DTOs for client-facing endpoints.",
    },
};

export const P1319_PASSWORD_OR_TOKEN_FIELD_IN_RESPONSE_OBJECT = {
    id: "P1319_PASSWORD_OR_TOKEN_FIELD_IN_RESPONSE_OBJECT",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "CRITICAL",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["res.json", "render json", "jsonify", "return", "response"], withinChars: 320 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(passwordHash|password_hash|password_digest|hashedPassword|resetToken|reset_token|refreshToken|refresh_token|apiKey|api_key)\\b\\s*[:=]\\s*['\"\\w\\[\\{]",
        ],
        negativePatterns: ["(?i)\\b(const|let|var|def|function|async)\\b", "(?i)[:=]\\s*\\w+\\("]
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "API Responses", shortLabel: "Sensitive field in response", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Sensitive credential/token field included in API response",
        description: "Response construction appears to include password hashes or authentication tokens/keys.",
        risk: "Leaking password hashes or tokens can enable account takeover and offline cracking. This is high-impact exposure.",
        confidenceRationale: "Field names are explicit and directly indicative of sensitive credential material.",
        recommendation: "Never return password hashes or secret tokens/keys to clients. Remove the field and rotate any exposed tokens if already deployed.",
    },
};

/* -------------------------
 * Postgres RLS signals
 * ------------------------- */

export const P1320_POSTGRES_RLS_DISABLED_OR_ROW_SECURITY_OFF = {
    id: "P1320_POSTGRES_RLS_DISABLED_OR_ROW_SECURITY_OFF",
    tier: "TIER_1",
    kind: "WARN",
    category: "Data Privacy & GDPR",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{sql,rb,py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["row level security", "row_security", "ALTER TABLE", "RLS", "policy"], withinChars: 620 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\balter\\s+table\\s+\\S+\\s+disable\\s+row\\s+level\\s+security\\b",
            "(?i)\\bset\\s+row_security\\s*=\\s*off\\b",
            "(?i)\\bset\\s+local\\s+row_security\\s*=\\s*off\\b",
        ],
    },
    presentation: { group: "Data Privacy & GDPR", subgroup: "Postgres RLS", shortLabel: "RLS disabled", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Row-Level Security appears explicitly disabled",
        description: "A migration/SQL change disables Postgres Row-Level Security or sets `row_security=off`.",
        risk: "Disabling RLS can bypass tenant isolation controls and cause cross-tenant data exposure in multi-tenant systems.",
        confidenceRationale: "The disable directives are explicit and deterministic.",
        recommendation: "Avoid disabling RLS in application paths. If temporarily required for maintenance, strictly scope usage and ensure it cannot run in normal request flows.",
    },
};

/* -------------------------
 * Logging / PII rules (from legacy)
 * ------------------------- */

export const P1321_LOGGING_SENSITIVE_HEADERS = {
    id: "P1321_LOGGING_SENSITIVE_HEADERS",
    tier: "TIER_1", kind: "WARN", category: "Data Privacy & GDPR", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(console\\.log|logger\\.|print|puts|error_log)\\b[^\\n]{0,100}\\b(authorization|cookie|set-cookie|token|password|secret)\\b"
        ]
    },
    explanation: {
        title: "Logging of sensitive headers or secrets",
        description: "Logging statement includes sensitive keywords like 'authorization' or 'cookie'.",
        risk: "Leaking credentials or session identifiers into logs can lead to unauthorized access if log stores are compromised.",
        confidenceRationale: "Common pattern for accidental credential logging; requires manual verification of the logged value.",
        recommendation: "Ensure all logs are redacted. Never log Authorization headers or session cookies."
    }
};

export const P1322_LOGGING_FULL_REQUEST = {
    id: "P1322_LOGGING_FULL_REQUEST",
    tier: "TIER_1", kind: "WARN", category: "Data Privacy & GDPR", severity: "LOW", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)\\b(console\\.log|logger\\.|print|puts|error_log)\\b[^\\n]{0,100}\\b(req\\.body|request\\.data|params|\\$_POST)\\b"
        ]
    },
    explanation: {
        title: "Full request body/params logged",
        description: "Code logs the entire request body or parameter set.",
        risk: "Wholesale logging increases the risk of capturing PII, passwords, or tokens that may be present in request data.",
        confidenceRationale: "Heuristic: logging request objects is a common but risky practice.",
        recommendation: "Log only specific, non-sensitive transaction IDs or metadata. Avoid logging raw user input."
    }
};

export const WARN_GDPR_RULES = [
    P1301_SCHEMA_SSN_COLUMN,
    P1302_SCHEMA_NATIONAL_ID_TAX_ID_COLUMN,
    P1303_SCHEMA_PASSPORT_OR_LICENSE_COLUMN,
    P1304_SCHEMA_CARD_NUMBER_OR_CVV_COLUMN,
    P1305_SCHEMA_DOB_BIRTHDATE_COLUMN,
    P1306_SCHEMA_PHONE_COLUMN,
    P1307_SCHEMA_ADDRESS_COLUMN,
    P1308_SCHEMA_EMAIL_COLUMN,
    P1309_SCHEMA_PASSWORD_FIELD_NOT_HASH,
    P1310_EXPRESS_RES_JSON_USER_OBJECT,
    P1311_EXPRESS_SPREAD_USER_OBJECT,
    P1312_RAILS_RENDER_JSON_USER,
    P1313_DJANGO_SERIALIZER_FIELDS_ALL,
    P1314_PYTHON_RETURN_USER_DICT,
    P1315_GRAPHQL_SCHEMA_PASSWORD_FIELD,
    P1316_SELECT_STAR_USERS_IN_HANDLER,
    P1317_PRISMA_FIND_WITHOUT_SELECT_AND_RETURN,
    P1318_SEQUELIZE_FIND_WITHOUT_ATTRIBUTES_AND_RETURN,
    P1319_PASSWORD_OR_TOKEN_FIELD_IN_RESPONSE_OBJECT,
    P1320_POSTGRES_RLS_DISABLED_OR_ROW_SECURITY_OFF,
    P1321_LOGGING_SENSITIVE_HEADERS,
    P1322_LOGGING_FULL_REQUEST
];
