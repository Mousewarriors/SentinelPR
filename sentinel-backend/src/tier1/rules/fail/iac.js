/**
 * Infrastructure-as-Code (K8s, Terraform, CloudFormation) FAIL rules
 */

// --- Kubernetes ---

export const K8S001_PRIVILEGED_CONTAINER = {
    id: "K8S001_PRIVILEGED_CONTAINER",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["K8S_MANIFEST_CONTEXT", "PRIVILEGED_TRUE"], withinSameHunk: true }
    },
    explanation: {
        title: "Privileged container detected",
        description: "Kubernetes manifest configures a container to run in privileged mode.",
        risk: "Privileged containers have nearly all the same access as processes running on the host, which can lead to host escape and full cluster compromise.",
        confidenceRationale: "The flag 'privileged: true' is a direct and high-risk security configuration.",
        recommendation: "Avoid privileged containers. Use specific Linux capabilities or Pod Security Policies/Standards instead."
    }
};

export const K8S002_HOST_NAMESPACE_SHARING = {
    id: "K8S002_HOST_NAMESPACE_SHARING",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: { type: "REGEX", patterns: ["hostNetwork:\\s*true", "hostPID:\\s*true", "hostIPC:\\s*true"] },
    explanation: {
        title: "Host namespace sharing enabled",
        description: "Kubernetes manifest enables sharing of host network, PID, or IPC namespaces.",
        risk: "Namespace sharing allows a container to see and interact with host processes and network traffic, significantly increasing the risk of host compromise.",
        confidenceRationale: "These flags are explicit and widely recognized as dangerous for standard containers.",
        recommendation: "Disable host namespace sharing. Use service meshes or CNI plugins for advanced networking needs."
    }
};

export const K8S003_HOSTPATH_VOLUME = {
    id: "K8S003_HOSTPATH_VOLUME",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: { allOf: ["K8S_POD_SPEC_CONTEXT", "K8S_HOSTPATH_VOL"], withinSameHunk: true }
    },
    explanation: {
        title: "hostPath volume mount detected",
        description: "Kubernetes manifest uses a hostPath volume mount.",
        risk: "hostPath allows a pod to access the host filesystem. If the pod is compromised, the attacker can access sensitive host files, including kubelet credentials or other pod data.",
        confidenceRationale: "Pattern matches the explicit volume type configuration.",
        recommendation: "Use persistentVolumeClaims or emptyDir instead of hostPath. If hostPath is required, restrict it to read-only where possible."
    }
};

export const K8S004_ALLOW_PRIVILEGE_ESCALATION = {
    id: "K8S004_ALLOW_PRIVILEGE_ESCALATION",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: { type: "REGEX", patterns: ["allowPrivilegeEscalation:\\s*true"] },
    explanation: {
        title: "Privilege escalation allowed",
        description: "Kubernetes manifest explicitly allows privilege escalation.",
        risk: "Allowing privilege escalation enables a process to gain more privileges than its parent, which can be used in exploit chains to gain root access.",
        confidenceRationale: "The flag is explicit in the securityContext.",
        recommendation: "Set allowPrivilegeEscalation: false for all containers."
    }
};

export const K8S005_RUN_AS_NON_ROOT_FALSE = {
    id: "K8S005_RUN_AS_NON_ROOT_FALSE",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: { type: "REGEX", patterns: ["runAsNonRoot:\\s*false"] },
    explanation: {
        title: "Explicitly allowed to run as root",
        description: "Kubernetes manifest explicitly sets runAsNonRoot to false.",
        risk: "Running as root inside a container increases the impact of a container breakout or vulnerability exploitation.",
        confidenceRationale: "The flag is explicit; failing because 'false' was explicitly requested.",
        recommendation: "Set runAsNonRoot: true and ensure images are built to run as a non-privileged user."
    }
};

// --- Terraform ---

export const TF001_SG_OPEN_SENSITIVE_PORT = {
    id: "TF001_SG_OPEN_SENSITIVE_PORT",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.tf", "**/*.tfvars"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["TF_SG_WORLD_OPEN", "TF_SG_SENSITIVE_PORT"],
            withinSameHunk: true
        }
    },
    explanation: {
        title: "Security group open to the world on sensitive port",
        description: "Terraform configuration opens a security group to 0.0.0.0/0 on a sensitive port (e.g., 22, 3306, 5432).",
        risk: "Exposing sensitive management or database ports to the entire internet allows for brute-force attacks and direct exploitation of database vulnerabilities.",
        confidenceRationale: "Rule triggers only when both 0.0.0.0/0 and a list of sensitive ports are found in the same hunk.",
        recommendation: "Restrict security group ingress to specific, trusted CIDR blocks or use VPC endpoints/bastion hosts."
    }
};

export const TF002_S3_BUCKET_PUBLIC = {
    id: "TF002_S3_BUCKET_PUBLIC",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.tf", "**/*.tfvars"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "acl\\s*=\\s*\"public-read\"",
            "acl\\s*=\\s*\"public-read-write\"",
            "block_public_acls\\s*=\\s*false",
            "block_public_policy\\s*=\\s*false",
            "ignore_public_acls\\s*=\\s*false",
            "restrict_public_buckets\\s*=\\s*false"
        ]
    },
    explanation: {
        title: "S3 bucket explicitly public",
        description: "Terraform configuration explicitly sets an S3 bucket or its access block to public.",
        risk: "Public S3 buckets are a leading cause of massive data breaches via accidental exposure of sensitive files.",
        confidenceRationale: "Triggers on explicit public ACLs or disabling of public access blocks.",
        recommendation: "Ensure S3 buckets are private. Enable all 'Block Public Access' settings and use CloudFront with OAI for public content serving."
    }
};

export const TF003_IAM_WILDCARD_ALL = {
    id: "TF003_IAM_WILDCARD_ALL",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.tf", "**/*.tfvars", "**/*.json"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["IAM_ACTION_WILDCARD", "IAM_RESOURCE_WILDCARD"],
            withinSameHunk: true
        }
    },
    explanation: {
        title: "IAM policy with wildcard Action and Resource",
        description: "IAM policy grants '*' (all) actions on '*' (all) resources.",
        risk: "Wildcard policies violate the principle of least privilege, allowing an identity to perform any action on any resource in the account, which can be catastrophic if the identity is compromised.",
        confidenceRationale: "Rule triggers only when both Action and Resource are set to a wildcard in the same policy block.",
        recommendation: "Scope IAM policies to specific actions and specific resource ARNs."
    }
};

// --- CloudFormation ---

export const CF001_SG_OPEN_SENSITIVE_PORT = {
    id: "CF001_SG_OPEN_SENSITIVE_PORT",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["CF_SG_WORLD_OPEN", "CF_SG_SENSITIVE_PORT"],
            withinSameHunk: true
        }
    },
    explanation: {
        title: "CloudFormation SG open to world on sensitive port",
        description: "CloudFormation template opens a Security Group to 0.0.0.0/0 on sensitive ports.",
        risk: "Publicly accessible sensitive ports are high-value targets for attackers.",
        confidenceRationale: "Matches explicit CidrIp: 0.0.0.0/0 and sensitive ports in the same resource.",
        recommendation: "Restrict ingress to specific IP ranges."
    }
};

export const CF002_S3_BUCKET_PUBLIC = {
    id: "CF002_S3_BUCKET_PUBLIC",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "CRITICAL", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "REGEX",
        patterns: [
            "AccessControl:\\s*(PublicRead|PublicReadWrite)",
            "Principal:\\s*\"\\*\"",
            "Principal:\\s*'*\\*'*",
            "Action:\\s*s3:GetObject"
        ]
    },
    explanation: {
        title: "CloudFormation S3 bucket/policy is public",
        description: "CloudFormation configuration grants public access to an S3 bucket.",
        risk: "Unintended data exposure via public S3 policies.",
        confidenceRationale: "Matches explicit PublicRead ACLs or wildcard Principals in S3 policies.",
        recommendation: "Ensure S3 buckets and policies do not allow anonymous access."
    }
};

export const CF003_IAM_WILDCARD_ALL = {
    id: "CF003_IAM_WILDCARD_ALL",
    tier: "TIER_1", kind: "FAIL", category: "Infrastructure-as-Code", severity: "HIGH", defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_AND_CONTEXT" },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true },
    detection: {
        type: "COMPOSITE",
        composite: {
            allOf: ["IAM_ACTION_WILDCARD", "IAM_RESOURCE_WILDCARD"],
            withinSameHunk: true
        }
    },
    explanation: {
        title: "CloudFormation IAM wildcard policy",
        description: "IAM policy in CloudFormation grants full access (* on *).",
        risk: "Excessive privileges allow full account compromise.",
        confidenceRationale: "Triggers on explicit Action: * and Resource: * within the same Statement.",
        recommendation: "Restrict IAM statements to specific actions and resources."
    }
};

// DOCKER001: Dockerfile runs as root (missing USER directive / explicit USER root)
export const DOCKER001_RUNS_AS_ROOT = {
    id: "DOCKER001_RUNS_AS_ROOT",
    tier: "TIER_1",
    kind: "FAIL",
    category: "IaC & Cloud Config",
    severity: "HIGH",
    appliesTo: { fileGlobs: ["**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: false, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // Explicit USER root
            "(?i)^\\s*USER\\s+(root|0)\\s*$"
        ]
    },
    explanation: {
        title: "Container runs as root",
        description: "Dockerfile sets the runtime user to root (or UID 0).",
        risk: "If the container is compromised, the attacker has root within the container. In misconfigured environments this can lead to full host compromise or lateral movement.",
        confidenceRationale: "USER root is an unambiguous instruction with no legitimate production use case.",
        recommendation: "Create a non-root user with RUN useradd -r appuser and apply USER appuser before the ENTRYPOINT/CMD instruction."
    }
};

// DOCKER002: Sensitive file or secret copied into Docker image
export const DOCKER002_SENSITIVE_FILE_COPY = {
    id: "DOCKER002_SENSITIVE_FILE_COPY",
    tier: "TIER_1",
    kind: "FAIL",
    category: "IaC & Cloud Config",
    severity: "CRITICAL",
    appliesTo: { fileGlobs: ["**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"], scanMode: "DIFF", diffLines: "ADDED_ONLY", textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true },
    detection: {
        type: "REGEX",
        patterns: [
            // COPY .env into image
            "(?i)^\\s*(COPY|ADD)\\s+[^\\n]*(\\.(env|pem|key|p12|pfx|crt|cer|jks|keystore|pkcs12)|(id_rsa|id_ecdsa|id_ed25519|secrets?\\/))",
            // COPY . (everything including .env / keys)
            "(?i)^\\s*(COPY|ADD)\\s+\\.\\s+"
        ]
    },
    explanation: {
        title: "Sensitive file or secret copied into Docker image",
        description: "A COPY or ADD instruction in the Dockerfile includes sensitive files (.env, .pem, private keys, keystores) or copies the entire current directory.",
        risk: "Files baked into Docker images are visible in image layers to anyone with pull access and in any environment the image is deployed to, permanently exposing secrets.",
        confidenceRationale: "File extensions and patterns for secrets/keys are unambiguous and almost never appropriate inside a container image.",
        recommendation: "Use Docker secrets, environment variables, or a secret manager at runtime. Never bake .env files, private keys, or certificates into images. Use .dockerignore to prevent accidental inclusion."
    }
};

export const FAIL_IAC_RULES = [
    K8S001_PRIVILEGED_CONTAINER, K8S002_HOST_NAMESPACE_SHARING, K8S003_HOSTPATH_VOLUME, K8S004_ALLOW_PRIVILEGE_ESCALATION, K8S005_RUN_AS_NON_ROOT_FALSE,
    TF001_SG_OPEN_SENSITIVE_PORT, TF002_S3_BUCKET_PUBLIC, TF003_IAM_WILDCARD_ALL,
    CF001_SG_OPEN_SENSITIVE_PORT, CF002_S3_BUCKET_PUBLIC, CF003_IAM_WILDCARD_ALL,
    DOCKER001_RUNS_AS_ROOT, DOCKER002_SENSITIVE_FILE_COPY
];
