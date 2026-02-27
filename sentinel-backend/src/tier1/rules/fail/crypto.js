/**
 * Cryptography FAIL rules
 *
 * Philosophy:
 * - Only fire on patterns that are unambiguously broken regardless of context.
 * - Weak cipher in a WARN already covers mentions; here we require proof of
 *   active USE via a function call with a provably broken algorithm name.
 * - Hardcoded zero/literal IV breaks CBC/CTR semantics by design; no safe use case.
 */

// CRYPT001: Broken cipher algorithm used as an active call argument
export const CRYPT001_BROKEN_CIPHER_ALGO = {
    id: "CRYPT001_BROKEN_CIPHER_ALGO",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Cryptography",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.{js,ts,py,rb,java,go,php,cs}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Node.js: createCipher/createDecipher with des, rc4, rc2, blowfish, idea
            "(?i)\\bcreate(Cipher|Decipher)\\s*\\(\\s*['\"]\\s*(des|des-ecb|des-cbc|des-cfb|des-ofb|rc4|rc2|bf|blowfish|idea)",
            // Python: Cipher.new with algo object, e.g. DES.new(key, ...)
            "(?i)\\b(DES|RC4|RC2|Blowfish|IDEA)\\s*\\.\\s*new\\s*\\(",
            // Java: Cipher.getInstance("DES/...") or Cipher.getInstance("RC4")
            "(?i)Cipher\\.getInstance\\s*\\(\\s*[\"'](DES|RC4|RC2|Blowfish|IDEA)[/\"']",
            // Generic: AES in ECB mode is also broken — createCipheriv('aes-*-ecb', ...)
            "(?i)\\bcreate(Cipher|Decipher)iv\\s*\\(\\s*['\"][^'\"]*-ecb['\"]"
        ]
    },
    explanation: {
        title: "Broken or deprecated cipher algorithm",
        description: "Code actively uses a broken cipher algorithm (DES, RC4, RC2, Blowfish, or ECB mode) as a cipher call argument.",
        risk: "DES has a 56-bit key space (brute-forceable). RC4 has multiple practical biases. ECB mode leaks data patterns. These algorithms MUST NOT be used for new implementations.",
        confidenceRationale: "The cipher name appears as a function call argument — this is active usage, not a comment or documentation reference.",
        recommendation: "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption. Never use DES, RC4, RC2, Blowfish, or ECB mode in new code."
    }
};

// CRYPT002: Hardcoded zero or all-same-byte IV
export const CRYPT002_HARDCODED_ZERO_IV = {
    id: "CRYPT002_HARDCODED_ZERO_IV",
    tier: "TIER_1",
    kind: "FAIL",
    category: "Cryptography",
    severity: "HIGH",
    appliesTo: {
        fileGlobs: ["**/*.{js,ts,py,rb,java,go,php,cs}"],
        scanMode: "DIFF",
        diffLines: "ADDED_ONLY",
        textOnly: true
    },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Node.js: Buffer.alloc(16, 0) / Buffer.alloc(8, 0) etc as IV
            "(?i)\\bcreate(Cipher|Decipher)iv\\b.{0,200}Buffer\\.alloc\\(\\s*(8|12|16|24|32)\\s*,\\s*0\\s*\\)",
            // Node.js: createCipheriv with a string of zeros as IV
            "(?i)\\bcreate(Cipher|Decipher)iv\\b.*['\"]0{8,}['\"]",
            // Python: iv = b'\\x00' * 16 or similar
            "(?i)\\biv\\s*=\\s*b['\"]?\\\\x00['\"]?\\s*\\*\\s*(8|12|16|24|32)",
            // Java/generic: new IvParameterSpec(new byte[16])
            "(?i)new\\s+IvParameterSpec\\s*\\(\\s*new\\s+byte\\s*\\[\\s*(8|12|16|24|32)\\s*\\]\\s*\\)"
        ]
    },
    explanation: {
        title: "Hardcoded zero/static IV in cipher",
        description: "A cipher is initialised with an all-zero or hardcoded static initialisation vector (IV).",
        risk: "A fixed IV completely breaks the semantic security of CBC and CTR modes — identical plaintexts produce identical ciphertexts, enabling ciphertext analysis and plaintext recovery.",
        confidenceRationale: "The zero IV is passed inline to the cipher call — this is active usage with no ambiguity.",
        recommendation: "Generate a cryptographically random IV for every encryption operation using crypto.randomBytes(16) or equivalent. Prepend the IV to the ciphertext for decryption."
    }
};

export const FAIL_CRYPTO_RULES = [
    CRYPT001_BROKEN_CIPHER_ALGO,
    CRYPT002_HARDCODED_ZERO_IV
];
