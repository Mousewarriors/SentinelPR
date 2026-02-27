/**
 * Crypto & Transport WARN rules
 *
 * Philosophy:
 * - Crypto & transport misconfigurations are common and high-impact,
 *   but many are context-dependent, so we emit WARN not FAIL.
 * - This pack stays low-noise by focusing on patterns almost always unsafe.
 */

export const T701_TLS_VERIFICATION_DISABLED = {
    id: "T701_TLS_VERIFICATION_DISABLED",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx,py,rb,php,java,go,cs,sh,bash,yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)insecure\\s*skip\\s*verify", "(?i)rejectUnauthorized\\s*:\\s*false", "(?i)verify\\s*=\\s*False", "(?i)CURLOPT_SSL_VERIFYPEER\\s*,\\s*0", "(?i)CURLOPT_SSL_VERIFYHOST\\s*,\\s*0", "(?i)VERIFY_NONE"] },
    presentation: { group: "Crypto & Transport", subgroup: "TLS", shortLabel: "TLS verify off", maxFindingsPerPR: 4, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "TLS certificate verification may be disabled", description: "Code includes patterns that commonly disable TLS certificate verification.", risk: "Disabling TLS verification enables man-in-the-middle attacks and can expose credentials, tokens, and sensitive data in transit.", confidenceRationale: "These settings are explicit and widely considered unsafe outside narrowly controlled development scenarios.", recommendation: "Enable certificate verification. If a custom CA is needed, configure trusted roots instead of disabling verification." }
};

export const T702_NODE_REJECT_UNAUTHORIZED_FALSE = {
    id: "T702_NODE_REJECT_UNAUTHORIZED_FALSE",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,jsx,tsx}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)rejectUnauthorized\\s*:\\s*false", "(?i)process\\.env\\.NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*['\"]0['\"]"] },
    presentation: { group: "Crypto & Transport", subgroup: "TLS", shortLabel: "Node TLS", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Node.js TLS verification disabled", description: "Node.js TLS verification appears disabled via rejectUnauthorized:false or NODE_TLS_REJECT_UNAUTHORIZED=0.", risk: "This permits MITM attacks and can leak secrets or allow response tampering.", confidenceRationale: "These are direct, unambiguous configuration patterns in Node.js.", recommendation: "Remove the override and configure proper trust stores / CA bundles for internal services." }
};

export const T703_PYTHON_VERIFY_FALSE = {
    id: "T703_PYTHON_VERIFY_FALSE",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{py}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["\\bverify\\s*=\\s*False\\b", "\\brequests\\.[a-z]+\\([^\\)]*verify\\s*=\\s*False"] },
    presentation: { group: "Crypto & Transport", subgroup: "TLS", shortLabel: "requests verify", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Python TLS verification disabled", description: "Python requests call disables TLS verification (verify=False).", risk: "Allows MITM and response tampering, potentially exposing tokens and sensitive data.", confidenceRationale: "verify=False is explicit and unambiguous.", recommendation: "Remove verify=False and configure CA bundles or use mTLS as needed." }
};

export const T704_JAVA_INSECURE_TRUST_MANAGER = {
    id: "T704_JAVA_INSECURE_TRUST_MANAGER",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{java,kt}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)X509TrustManager", "(?i)checkServerTrusted\\s*\\(.*\\)\\s*\\{\\s*\\}", "(?i)TrustAllCerts|TrustAllCertificates|InsecureTrustManager"] },
    presentation: { group: "Crypto & Transport", subgroup: "TLS", shortLabel: "Trust manager", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Java insecure TrustManager pattern", description: "Code appears to implement or reference a TrustManager that may accept all certificates.", risk: "Accepting all certificates defeats TLS security and enables MITM attacks.", confidenceRationale: "TrustManager usage is clear, but determining whether it truly trusts all certs can require deeper analysis.", recommendation: "Use the default TrustManager or a properly configured trust store. Avoid trust-all implementations." }
};

export const T705_GO_INSECURE_SKIP_VERIFY = {
    id: "T705_GO_INSECURE_SKIP_VERIFY",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{go}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)InsecureSkipVerify\\s*:\\s*true"] },
    presentation: { group: "Crypto & Transport", subgroup: "TLS", shortLabel: "Go TLS", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Go TLS verification disabled", description: "Go TLS config sets InsecureSkipVerify: true.", risk: "Permits MITM and response tampering, exposing credentials and sensitive data.", confidenceRationale: "InsecureSkipVerify is explicit and unambiguous.", recommendation: "Remove InsecureSkipVerify and configure RootCAs or ServerName correctly." }
};

export const T706_RUBY_OPENSSL_VERIFY_NONE = {
    id: "T706_RUBY_OPENSSL_VERIFY_NONE",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{rb}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["OpenSSL::SSL::VERIFY_NONE", "verify_mode\\s*=\\s*OpenSSL::SSL::VERIFY_NONE"] },
    presentation: { group: "Crypto & Transport", subgroup: "TLS", shortLabel: "Ruby TLS", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Ruby TLS verification disabled", description: "Ruby OpenSSL verify_mode is set to VERIFY_NONE.", risk: "Disables certificate validation, enabling MITM attacks.", confidenceRationale: "VERIFY_NONE is explicit and unambiguous.", recommendation: "Use VERIFY_PEER and configure trusted CA certificates properly." }
};

export const T707_PHP_CURL_SSL_VERIFY_OFF = {
    id: "T707_PHP_CURL_SSL_VERIFY_OFF",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{php}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["CURLOPT_SSL_VERIFYPEER\\s*,\\s*(false|0)", "CURLOPT_SSL_VERIFYHOST\\s*,\\s*(false|0)"] },
    presentation: { group: "Crypto & Transport", subgroup: "TLS", shortLabel: "PHP cURL TLS", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "PHP cURL TLS verification disabled", description: "PHP cURL options disable certificate/host verification.", risk: "Disabling TLS verification enables MITM attacks and response tampering.", confidenceRationale: "These cURL options are explicit and unambiguous.", recommendation: "Enable verification and configure CA bundle correctly. Do not use verify-off in production." }
};

export const T708_HTTP_USED_FOR_TOKEN_OR_AUTH = {
    id: "T708_HTTP_USED_FOR_TOKEN_OR_AUTH",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs,yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["token", "oauth", "auth", "login", "jwt", "bearer"], withinChars: 200 } },
    detection: { type: "REGEX", patterns: ["\\bhttp://[^\\s'\"]+\\b"] },
    presentation: { group: "Crypto & Transport", subgroup: "Transport", shortLabel: "HTTP auth", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "HTTP used for token/auth-related request", description: "A token/auth-related URL appears to use http:// instead of https://.", risk: "Credentials and tokens can be intercepted or modified in transit over HTTP.", confidenceRationale: "http:// is deterministic; association with auth is inferred via nearby keywords.", recommendation: "Use HTTPS for all authentication and token endpoints." }
};

export const T709_WEAK_PASSWORD_HASH_MD5_SHA1 = {
    id: "T709_WEAK_PASSWORD_HASH_MD5_SHA1",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["password", "passwd", "pwd", "hash"], withinChars: 200 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(md5|sha1)\\b"] },
    presentation: { group: "Crypto & Transport", subgroup: "Password hashing", shortLabel: "Weak hash", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Weak hash algorithm in password context", description: "MD5 or SHA1 appears used near password-hashing logic.", risk: "MD5/SHA1 are fast hashes and unsuitable for password storage; they are vulnerable to brute-force and rainbow table attacks.", confidenceRationale: "Algorithm mention is deterministic; password association is inferred via nearby keywords.", recommendation: "Use a password hashing function such as bcrypt, scrypt, Argon2, or PBKDF2 with strong parameters." }
};

export const T710_INSECURE_RANDOMNESS = {
    id: "T710_INSECURE_RANDOMNESS",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["token", "secret", "session", "nonce", "csrf", "jwt", "key"], withinChars: 220 } },
    detection: { type: "REGEX", patterns: ["\\bMath\\.random\\s*\\(", "\\brandom\\.rand(int)?\\s*\\(", "\\bjava\\.util\\.Random\\b", "\\brand\\s*\\("] },
    presentation: { group: "Crypto & Transport", subgroup: "Randomness", shortLabel: "Weak RNG", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Non-cryptographic randomness used in security-sensitive context", description: "A non-cryptographic RNG appears used near security-sensitive values (tokens, secrets, session IDs).", risk: "Predictable randomness can allow token guessing and session compromise.", confidenceRationale: "RNG API usage is deterministic; security context is inferred via nearby keywords.", recommendation: "Use cryptographically secure RNGs (Node crypto.randomBytes, Python secrets, Java SecureRandom, Go crypto/rand)." }
};

export const T711_JWT_NONE_ALGORITHM = {
    id: "T711_JWT_NONE_ALGORITHM",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\balg\\s*[:=]\\s*['\"]none['\"]", "(?i)\\bnone\\b\\s*\\)\\s*;?\\s*$"] },
    presentation: { group: "Crypto & Transport", subgroup: "JWT", shortLabel: "JWT none", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "JWT 'none' algorithm detected", description: "JWT code appears to allow or reference the 'none' algorithm.", risk: "Accepting alg=none can allow signature bypass, enabling attackers to forge tokens.", confidenceRationale: "'none' algorithm is explicit and almost never appropriate in production.", recommendation: "Reject alg=none and enforce a strict allowlist of expected JWT algorithms (e.g., RS256/ES256) with correct key usage." }
};

export const T712_JWT_ALGORITHM_FROM_INPUT = {
    id: "T712_JWT_ALGORITHM_FROM_INPUT",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["jwt", "verify", "decode", "algorithm", "alg"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)alg(orithm)?\\s*[:=]\\s*(req\\.|params\\.|query\\.|body\\.|input\\()", "(?i)jwt\\.(verify|decode)\\([^\\)]*(algorithms|algorithm)\\s*[:=]\\s*.*(req\\.|params\\.|query\\.|body\\.)"] },
    presentation: { group: "Crypto & Transport", subgroup: "JWT", shortLabel: "JWT alg input", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "JWT algorithm may be influenced by untrusted input", description: "JWT verification appears to accept algorithm choices derived from request/input values.", risk: "Algorithm confusion can allow attackers to bypass verification or force weaker algorithms.", confidenceRationale: "This is heuristic; safe use requires strict server-side allowlists.", recommendation: "Enforce a fixed allowlist of algorithms server-side; never allow clients to choose or influence JWT algorithms." }
};

export const T713_HARDCODED_CRYPTO_KEY_OR_IV = {
    id: "T713_HARDCODED_CRYPTO_KEY_OR_IV",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["key", "iv", "cipher", "encrypt", "decrypt", "aes", "rsa"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)\\b(key|iv)\\b\\s*[:=]\\s*['\"][A-Za-z0-9+/=]{16,}['\"]", "(?i)\\bAES\\b.*['\"][A-Za-z0-9+/=]{16,}['\"]"] },
    presentation: { group: "Crypto & Transport", subgroup: "Key management", shortLabel: "Hardcoded key", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Hardcoded crypto key/IV pattern", description: "A string that resembles a crypto key or IV appears hardcoded near encryption logic.", risk: "Hardcoded keys/IVs can be extracted from source, breaking confidentiality and allowing decryption/forgery.", confidenceRationale: "Heuristic: not all base64/hex strings are keys; stronger confirmation requires deeper parsing.", recommendation: "Load keys from a secret manager or environment variables. Avoid fixed IVs and use secure key management practices." }
};

export const T714_ECB_MODE_CIPHER = {
    id: "T714_ECB_MODE_CIPHER",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bECB\\b", "(?i)AES\\/ECB"] },
    presentation: { group: "Crypto & Transport", subgroup: "Ciphers", shortLabel: "ECB", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "ECB mode cipher detected", description: "ECB mode appears used for symmetric encryption.", risk: "ECB leaks patterns in plaintext and is not semantically secure.", confidenceRationale: "ECB references are explicit and almost always inappropriate for encrypting data.", recommendation: "Use AEAD modes like AES-GCM or ChaCha20-Poly1305, or CBC with random IV + authentication." }
};

export const T715_INSECURE_DES_CIPHER = {
    id: "T715_INSECURE_DES_CIPHER",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: { type: "REGEX", patterns: ["(?i)\\bDES\\b", "(?i)\\b3DES\\b", "(?i)DESede"] },
    presentation: { group: "Crypto & Transport", subgroup: "Ciphers", shortLabel: "DES/3DES", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "DES/3DES cipher usage detected", description: "Code references DES or 3DES encryption algorithms.", risk: "DES is broken and 3DES is deprecated due to weak security margins and practical attacks.", confidenceRationale: "DES/3DES references are explicit and widely considered unsafe for new implementations.", recommendation: "Use modern ciphers (AES-GCM or ChaCha20-Poly1305) and avoid DES/3DES entirely." }
};

export const T716_PBKDF2_ITERATIONS_LOW = {
    id: "T716_PBKDF2_ITERATIONS_LOW",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["pbkdf2", "iterations", "rounds", "deriveKey"], withinChars: 220 } },
    detection: { type: "REGEX", patterns: ["(?i)pbkdf2[^\\n]{0,120}(iterations|rounds)\\s*[:=]\\s*(\\d{1,4})"] },
    presentation: { group: "Crypto & Transport", subgroup: "KDF params", shortLabel: "PBKDF2", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "PBKDF2 iterations may be low", description: "PBKDF2 usage appears configured with a low iteration count.", risk: "Low iteration counts make password hashes cheaper to brute-force if the database is compromised.", confidenceRationale: "Heuristic: parsing numeric parameters reliably in diffs is difficult and thresholds vary over time.", recommendation: "Follow current guidance for PBKDF2 iteration counts or use bcrypt/Argon2 with strong parameters." }
};

export const T717_BCRYPT_COST_LOW = {
    id: "T717_BCRYPT_COST_LOW",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["bcrypt", "cost", "rounds"], withinChars: 200 } },
    detection: { type: "REGEX", patterns: ["(?i)bcrypt[^\\n]{0,120}(rounds|cost)\\s*[:=]\\s*(\\d{1,2})"] },
    presentation: { group: "Crypto & Transport", subgroup: "Password hashing", shortLabel: "bcrypt cost", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "bcrypt cost parameter may be low", description: "bcrypt usage appears configured with a low cost/rounds setting.", risk: "Low cost reduces resistance to offline cracking after a credential database compromise.", confidenceRationale: "Heuristic: thresholds vary and numeric parsing can be brittle; keep as low-noise WARN only.", recommendation: "Use a cost factor aligned with current guidance and performance budgets, and re-evaluate periodically." }
};

export const T718_ARGON2_PARAMS_WEAK = {
    id: "T718_ARGON2_PARAMS_WEAK",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["argon2", "memory", "timeCost", "parallelism"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)argon2[^\\n]{0,200}(memory|time|parallelism)\\s*[:=]\\s*(\\d{1,6})"] },
    presentation: { group: "Crypto & Transport", subgroup: "Password hashing", shortLabel: "Argon2", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Argon2 parameters may be weak", description: "Argon2 appears configured with potentially weak parameters (memory/time/parallelism).", risk: "Weak Argon2 settings reduce resistance to offline cracking.", confidenceRationale: "Heuristic: numeric thresholds vary and require context; keep WARN and low frequency.", recommendation: "Follow current Argon2 parameter guidance and tune based on server performance budgets." }
};

export const T719_DISABLE_HSTS_OR_SECURE_COOKIES = {
    id: "T719_DISABLE_HSTS_OR_SECURE_COOKIES",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "MEDIUM", defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["HSTS", "Strict-Transport-Security", "cookie", "secure", "httponly", "samesite"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)Strict-Transport-Security", "(?i)\\bsecure\\s*:\\s*false\\b", "(?i)\\bhttpOnly\\s*:\\s*false\\b", "(?i)\\bsameSite\\s*:\\s*['\"]none['\"]\\b"] },
    presentation: { group: "Crypto & Transport", subgroup: "Web transport", shortLabel: "Headers/cookies", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: { title: "Transport security header/cookie settings may be weakened", description: "Code changes indicate HSTS/cookie security flags may be missing or disabled.", risk: "Weak transport headers and cookie flags can increase risk of session theft, downgrade attacks, and cross-site attacks.", confidenceRationale: "Settings are detectable, but some are environment-specific (e.g., SameSite=None for cross-site flows).", recommendation: "Enable HSTS in production and ensure cookies are Secure, HttpOnly, and use appropriate SameSite settings." }
};

export const T720_MTLS_OR_CERT_PINNING_DISABLED = {
    id: "T720_MTLS_OR_CERT_PINNING_DISABLED",
    tier: "TIER_1", kind: "WARN", category: "Crypto & Transport", severity: "MEDIUM", defaultConfidence: "LOW",
    appliesTo: { fileGlobs: ["**/*.{js,ts,py,rb,php,java,go,cs}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT", maxFileSizeKB: 512, textOnly: true },
    triggerPolicy: { noise: "HIGH", minimumConfidenceToEmit: "LOW", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["pin", "certificate", "mtls", "client cert", "keyStore", "trustStore"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)disable.*pin", "(?i)pinning\\s*:\\s*false", "(?i)clientCertificateRequired\\s*:\\s*false"] },
    presentation: { group: "Crypto & Transport", subgroup: "Advanced transport", shortLabel: "Pinning/mTLS", maxFindingsPerPR: 1, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: false, showPreExisting: "HIDE" },
    explanation: { title: "Certificate pinning or mTLS may be disabled", description: "Code indicates that certificate pinning or mTLS requirements may be disabled.", risk: "Disabling these controls can reduce defense-in-depth for sensitive internal service communications.", confidenceRationale: "Heuristic: exact semantics vary by library and app architecture.", recommendation: "Only relax pinning/mTLS with explicit security review and compensate with strong TLS verification and network controls." }
};

export const WARN_CRYPTO_RULES = [
    T701_TLS_VERIFICATION_DISABLED, T702_NODE_REJECT_UNAUTHORIZED_FALSE, T703_PYTHON_VERIFY_FALSE, T704_JAVA_INSECURE_TRUST_MANAGER, T705_GO_INSECURE_SKIP_VERIFY, T706_RUBY_OPENSSL_VERIFY_NONE, T707_PHP_CURL_SSL_VERIFY_OFF, T708_HTTP_USED_FOR_TOKEN_OR_AUTH, T709_WEAK_PASSWORD_HASH_MD5_SHA1, T710_INSECURE_RANDOMNESS, T711_JWT_NONE_ALGORITHM, T712_JWT_ALGORITHM_FROM_INPUT, T713_HARDCODED_CRYPTO_KEY_OR_IV, T714_ECB_MODE_CIPHER, T715_INSECURE_DES_CIPHER, T716_PBKDF2_ITERATIONS_LOW, T717_BCRYPT_COST_LOW, T718_ARGON2_PARAMS_WEAK, T719_DISABLE_HSTS_OR_SECURE_COOKIES, T720_MTLS_OR_CERT_PINNING_DISABLED
];
