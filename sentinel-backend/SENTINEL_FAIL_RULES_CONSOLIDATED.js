/**
 * CONSOLIDATED TIER 1 FAIL RULES
 * 
 * This file contains all detection logic for TIER 1 FAIL rules.
 * Use this as a reference to ensure no clashing with new WARN packs.
 */

export const FAIL_RULES = [
    // --- 1. Secrets & Credentials ---
    {
        id: "S001", severity: "CRITICAL", title: "Private key committed", category: "Secrets & Credentials",
        appliesTo: { fileGlobs: ["**/*"], excludeGlobs: ["**/*.md", "**/docs/**", "**/examples/**", "**/tests/**"] },
        detection: {
            type: "REGEX",
            patterns: [
                "-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                "-----BEGIN PGP PRIVATE KEY BLOCK-----"
            ]
        },
        explanation: {
            title: "Private key committed",
            description: "A private key block was detected in the repository.",
            risk: "Committed private keys allow anyone with repository access to impersonate the owner, decrypt data, or access protected systems.",
            recommendation: "Revoke the key immediately, rotate it, and remove the file from history. Use a secret manager for production keys."
        }
    },
    {
        id: "S004", severity: "CRITICAL", title: "GitHub token committed", category: "Secrets & Credentials",
        detection: {
            type: "REGEX",
            requireValuePosition: true,
            patterns: ["ghp_[A-Za-z0-9]{36,}", "github_pat_[A-Za-z0-9_]{20,}", "gho_[A-Za-z0-9]{20,}"],
            negativePatterns: ["xxx", "example", "REDACTED", "YOUR_TOKEN_HERE"]
        },
        explanation: {
            title: "GitHub authentication token committed",
            description: "A GitHub Personal Access Token or OAuth token was added in a value position.",
            risk: "Committed tokens grant access to your GitHub account and repositories, potentially leading to unauthorized code changes or data theft.",
            recommendation: "Revoke the token in GitHub settings and use GitHub Actions secrets or environment variables."
        }
    },

    // --- 2. Serverless & Cloud Functions ---
    {
        id: "SF001_PUBLIC_FUNCTION_EXPOSURE",
        tier: "TIER_1", kind: "FAIL", category: "Serverless & Cloud Functions", severity: "CRITICAL",
        appliesTo: { fileGlobs: ["**/*.{yml,yaml,tf}", "serverless.*", "cloudbuild.*", "gcloud*", "firebase*"] },
        detection: {
            type: "REGEX",
            patterns: ["AuthType:\\s*NONE", "AuthorizationType:\\s*NONE", "--allow-unauthenticated", "allowUnauthenticated:\\s*true", "allUsers", "roles/run.invoker"],
            negativePatterns: ["ingress:\\s*internal", "ingress:\\s*private"]
        }
    },

    // --- 3. Infrastructure-as-Code (Kubernetes) ---
    {
        id: "K8S001_PRIVILEGED_CONTAINER",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["K8S_MANIFEST_CONTEXT", "PRIVILEGED_TRUE"] }
        }
    },
    {
        id: "K8S002_HOST_NAMESPACE_SHARING",
        detection: {
            type: "COMPOSITE",
            composite: {
                allOf: ["K8S_POD_SPEC_CONTEXT"],
                anyOf: ["HOST_NETWORK_TRUE", "HOST_PID_TRUE", "HOST_IPC_TRUE"]
            }
        }
    },
    {
        id: "K8S003_SENSITIVE_HOSTPATH_MOUNT",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["K8S_HOSTPATH_PRESENT", "HOSTPATH_SENSITIVE_TARGET"] }
        }
    },
    {
        id: "K8S005_ROOT_WITH_CAPABILITIES",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["RUN_AS_ROOT_TRUE", "CAPABILITIES_ADDED"] }
        }
    },

    // --- 4. Infrastructure-as-Code (Terraform) ---
    {
        id: "TF001_SG_OPEN_SENSITIVE_PORT",
        detection: { type: "COMPOSITE", composite: { allOf: ["TF_SG_WORLD_OPEN", "TF_SG_SENSITIVE_PORT"] } }
    },
    {
        id: "TF002_S3_BUCKET_PUBLIC",
        detection: {
            type: "REGEX",
            patterns: ["acl\\s*=\\s*\"public-read\"", "acl\\s*=\\s*\"public-read-write\"", "block_public_acls\\s*=\\s*false", "block_public_policy\\s*=\\s*false", "Principal\\s*[:=]\\s*\"\\*\""]
        }
    },
    {
        id: "TF003_IAM_WILDCARD_ADMIN",
        detection: {
            type: "COMPOSITE",
            composite: {
                allOf: ["IAM_ACTION_WILDCARD", "IAM_RESOURCE_WILDCARD"],
                noneOf: ["IAM_CONDITION_PRESENT"]
            }
        }
    },

    // --- 5. AI & LLM Security ---
    {
        id: "AI001_LLM_OUTPUT_EXEC",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["LLM_OUTPUT_PRESENT", "DANGEROUS_EXEC_SINK", "HAS_NEAR_SOURCE"] }
        }
    },

    // --- 6. Web & CORS ---
    {
        id: "SEC001_CORS_WILDCARD_WITH_CREDENTIALS",
        detection: { type: "COMPOSITE", composite: { allOf: ["CORS_WILDCARD_PRESENT", "CORS_CREDENTIALS_TRUE_PRESENT"] } }
    },
    {
        id: "SEC002_CSRF_DISABLED_WITH_COOKIES",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["CSRF_DISABLED_SIGNALS", "COOKIE_AUTH_MARKERS_PRESENT"] }
        }
    },
    {
        id: "SEC003_INSECURE_COOKIE_PROD",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["IS_PROD_CONTEXT", "COOKIE_SET_PRESENT", "COOKIE_FLAGS_WEAK"] }
        }
    },

    // --- 7. File & Path Traversal ---
    {
        id: "PATH001_USER_CONTROLLED_FILE_IO",
        detection: {
            type: "COMPOSITE",
            composite: {
                allOf: ["FILE_IO_SINK", "HAS_NEAR_SOURCE"],
                noneOf: ["HAS_NEAR_GUARD"]
            }
        }
    },
    // --- 8. Transport & Serialization (New Fails) ---
    {
        id: "T006_TLS_VERIFY_DISABLED_PROD",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["IS_PROD_CONTEXT", "SSL_VERIFY_DISABLED"] }
        }
    },
    {
        id: "E006_INSECURE_DESERIALIZATION",
        detection: {
            type: "COMPOSITE",
            composite: { allOf: ["DESERIALIZATION_SINK", "HAS_NEAR_SOURCE"] }
        }
    }
];
