// IaC WARN pack (H1201–H1220)
// - Single consolidated file per guidelines (no subfolders).
// - Diff-first (ADDED_ONLY), deterministic patterns where possible.
// - Complements existing FAIL rules (does not duplicate TF001/TF002/TF003, CF001/CF002/CF003, K8S001–K8S005).

export const H1201_TF_EBS_ENCRYPTION_DISABLED = {
    id: "H1201_TF_EBS_ENCRYPTION_DISABLED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["aws_ebs_volume", "ebs", "encrypted"], withinChars: 280 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bencrypted\\s*=\\s*false\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Terraform", shortLabel: "EBS unencrypted", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "EBS volume encryption explicitly disabled",
        description: "Terraform config sets `encrypted = false` for an EBS volume/snapshot.",
        risk: "Unencrypted block storage increases impact of snapshot/backup exposure and weakens compliance controls around data at rest.",
        confidenceRationale: "`encrypted = false` is explicit and reliably detectable.",
        recommendation: "Enable encryption (`encrypted = true`) and use KMS keys where required by policy.",
    },
};

export const H1202_TF_EC2_ROOT_VOLUME_ENCRYPTION_DISABLED = {
    id: "H1202_TF_EC2_ROOT_VOLUME_ENCRYPTION_DISABLED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["root_block_device", "ebs_block_device", "encrypted", "aws_instance"], withinChars: 320 } },
    detection: { type: "REGEX", patterns: ["(?i)(root_block_device|ebs_block_device)[\\s\\S]{0,220}\\bencrypted\\s*=\\s*false\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Terraform", shortLabel: "Root unencrypted", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "EC2 block device encryption explicitly disabled",
        description: "Terraform config disables encryption on an EC2 root/attached EBS block device.",
        risk: "Unencrypted root/attached volumes can expose sensitive application data and secrets stored on disk via snapshots or improper access.",
        confidenceRationale: "The `encrypted = false` setting is explicit and commonly actionable.",
        recommendation: "Enable EBS encryption on root and data volumes and standardize via account defaults/policies where possible.",
    },
};

export const H1203_TF_EBS_SNAPSHOT_ENCRYPTION_DISABLED = {
    id: "H1203_TF_EBS_SNAPSHOT_ENCRYPTION_DISABLED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 768, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["aws_ebs_snapshot", "snapshot", "encrypted"], withinChars: 280 } },
    detection: { type: "REGEX", patterns: ["(?i)resource\\s+\"aws_ebs_snapshot\"[\\s\\S]{0,420}\\bencrypted\\s*=\\s*false\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Terraform", shortLabel: "Snapshot unencrypted", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "EBS snapshot encryption explicitly disabled",
        description: "Terraform config disables encryption on an EBS snapshot.",
        risk: "Snapshots are frequently copied, shared, or used for restore workflows; lack of encryption increases data exposure risk.",
        confidenceRationale: "The snapshot resource and encryption flag are explicit in configuration.",
        recommendation: "Encrypt snapshots and ensure copy/restore workflows preserve encryption (prefer KMS-managed keys).",
    },
};

export const H1204_CF_EBS_ENCRYPTION_DISABLED = {
    id: "H1204_CF_EBS_ENCRYPTION_DISABLED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["AWS::EC2::Volume", "BlockDeviceMappings", "Ebs", "Encrypted"], withinChars: 380 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bEncrypted\\s*:\\s*false\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "CloudFormation", shortLabel: "EBS unencrypted", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "CloudFormation EBS encryption explicitly disabled",
        description: "CloudFormation sets `Encrypted: false` for an EBS volume or block device mapping.",
        risk: "Unencrypted volumes increase exposure risk through snapshots/backups and weaken data-at-rest controls.",
        confidenceRationale: "`Encrypted: false` is explicit and deterministic.",
        recommendation: "Set `Encrypted: true` and use KMS keys per your security policy.",
    },
};

export const H1205_K8S_RUNASUSER_ROOT = {
    id: "H1205_K8S_RUNASUSER_ROOT",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["securityContext", "runAsUser", "pod", "container"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\brunAsUser\\s*:\\s*0\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "Runs as root", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Container configured to run as root (runAsUser: 0)",
        description: "Kubernetes manifest sets `runAsUser: 0`.",
        risk: "Root containers increase impact of container escapes and make lateral movement easier after compromise.",
        confidenceRationale: "The value `0` is explicit and reliably detectable.",
        recommendation: "Run containers as a non-root UID and validate with admission policies (PSA/Gatekeeper/Kyverno).",
    },
};

export const H1206_K8S_READONLY_ROOT_FS_FALSE = {
    id: "H1206_K8S_READONLY_ROOT_FS_FALSE",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "MEDIUM",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["securityContext", "readOnlyRootFilesystem"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)\\breadOnlyRootFilesystem\\s*:\\s*false\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "Writable rootfs", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "readOnlyRootFilesystem disabled",
        description: "Kubernetes manifest sets `readOnlyRootFilesystem: false`.",
        risk: "Writable root filesystems can make persistence easier for attackers and increase risk of tampering with application binaries/configs.",
        confidenceRationale: "The setting is explicit; applicability depends on workload requirements.",
        recommendation: "Prefer `readOnlyRootFilesystem: true` and use writable volumes for required paths only.",
    },
};

export const H1207_K8S_SECCOMP_UNCONFINED = {
    id: "H1207_K8S_SECCOMP_UNCONFINED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["seccompProfile", "type", "securityContext"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bseccompProfile\\s*:\\s*[\\s\\S]{0,80}\\btype\\s*:\\s*Unconfined\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "seccomp off", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "seccomp set to Unconfined",
        description: "Kubernetes manifest sets `seccompProfile.type: Unconfined`.",
        risk: "Disabling seccomp removes syscall filtering and can increase impact of container breakout exploit chains.",
        confidenceRationale: "The Unconfined setting is explicit and deterministic.",
        recommendation: "Use `RuntimeDefault` (or a tailored profile) for containers handling sensitive workloads.",
    },
};

export const H1208_K8S_CAPABILITIES_ADD_ALL = {
    id: "H1208_K8S_CAPABILITIES_ADD_ALL",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["capabilities", "add", "securityContext"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bcapabilities\\s*:\\s*[\\s\\S]{0,120}\\badd\\s*:\\s*\\[[^\\]]*\\bALL\\b[^\\]]*\\]"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "caps: ALL", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Linux capabilities set to ALL",
        description: "Kubernetes manifest adds `ALL` capabilities to a container.",
        risk: "Extra Linux capabilities expand kernel-level privileges and increase impact of container compromise.",
        confidenceRationale: "The `ALL` token is explicit and reliably detectable.",
        recommendation: "Remove `ALL` and add only required capabilities (if any). Prefer dropping all capabilities by default.",
    },
};

export const H1209_K8S_CAPABILITIES_ADD_PRIVILEGED_ONES = {
    id: "H1209_K8S_CAPABILITIES_ADD_PRIVILEGED_ONES",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["capabilities", "add", "NET_ADMIN", "SYS_ADMIN", "securityContext"], withinChars: 320 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bcapabilities\\s*:\\s*[\\s\\S]{0,140}\\badd\\s*:\\s*\\[[^\\]]*\\b(NET_ADMIN|SYS_ADMIN)\\b[^\\]]*\\]"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "caps: admin", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Privileged Linux capabilities added (NET_ADMIN/SYS_ADMIN)",
        description: "Kubernetes manifest adds highly privileged capabilities (e.g., NET_ADMIN or SYS_ADMIN).",
        risk: "These capabilities can enable network manipulation or broad system-level operations, increasing breakout and lateral movement risk.",
        confidenceRationale: "Capability names are explicit and deterministic.",
        recommendation: "Avoid NET_ADMIN/SYS_ADMIN unless strictly required and reviewed; isolate workloads and use least privilege.",
    },
};

export const H1210_K8S_HOSTPORT_USED = {
    id: "H1210_K8S_HOSTPORT_USED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["hostPort", "ports", "containerPort"], withinChars: 240 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bhostPort\\s*:\\s*\\d+\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "hostPort", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "hostPort used in pod spec",
        description: "Kubernetes manifest exposes a container port directly on the node using `hostPort`.",
        risk: "hostPort bypasses some cluster networking controls and can unintentionally expose services on node IPs.",
        confidenceRationale: "hostPort usage is explicit and deterministic in YAML.",
        recommendation: "Avoid hostPort where possible; prefer Services/Ingress with explicit policies and network controls.",
    },
};

export const H1211_K8S_AUTOMOUNT_SERVICE_ACCOUNT_TOKEN_TRUE = {
    id: "H1211_K8S_AUTOMOUNT_SERVICE_ACCOUNT_TOKEN_TRUE",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "MEDIUM",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["automountServiceAccountToken", "serviceAccount", "pod"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bautomountServiceAccountToken\\s*:\\s*true\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "SAT mounted", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Service account token auto-mount enabled",
        description: "Kubernetes manifest explicitly enables `automountServiceAccountToken: true`.",
        risk: "Mounted service account tokens can be stolen from pods and used for Kubernetes API access if RBAC is too permissive.",
        confidenceRationale: "The setting is explicit; risk depends on RBAC scope of the service account.",
        recommendation: "Disable auto-mount when not needed (`false`) and ensure least-privilege RBAC for service accounts.",
    },
};

export const H1212_K8S_IMAGE_TAG_LATEST = {
    id: "H1212_K8S_IMAGE_TAG_LATEST",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "MEDIUM",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["image:", "containers:", "initContainers:"], withinChars: 260 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bimage\\s*:\\s*[^\\s]+:latest\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "image:latest", maxFindingsPerPR: 3, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Container image uses :latest tag",
        description: "Kubernetes manifest references an image with the mutable `:latest` tag.",
        risk: "Mutable tags weaken reproducibility and can introduce unreviewed image changes, complicating incident response and rollbacks.",
        confidenceRationale: "The `:latest` tag is explicit and deterministic.",
        recommendation: "Pin to versioned tags and ideally immutable digests (`@sha256:...`).",
    },
};

export const H1213_TF_SG_INGRESS_WORLD_ALL_PORTS = {
    id: "H1213_TF_SG_INGRESS_WORLD_ALL_PORTS",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["aws_security_group", "ingress", "cidr_blocks", "0.0.0.0/0", "from_port", "to_port"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)ingress[\\s\\S]{0,520}\\bcidr_blocks\\s*=\\s*\\[[^\\]]*\"0\\.0\\.0\\.0/0\"[^\\]]*\\][\\s\\S]{0,420}\\b(from_port\\s*=\\s*0\\b|to_port\\s*=\\s*65535\\b|protocol\\s*=\\s*\"-1\")",
            "(?i)resource\\s+\"aws_security_group_rule\"[\\s\\S]{0,620}\\bcidr_blocks\\s*=\\s*\\[[^\\]]*\"0\\.0\\.0\\.0/0\"[^\\]]*\\][\\s\\S]{0,260}\\b(from_port\\s*=\\s*0\\b|to_port\\s*=\\s*65535\\b|protocol\\s*=\\s*\"-1\")",
        ],
    },
    presentation: { group: "IaC (Big Three)", subgroup: "Terraform", shortLabel: "SG world all ports", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Security Group ingress allows the world on all ports/protocols",
        description: "Terraform security group ingress appears to allow `0.0.0.0/0` with all ports (0–65535) or all protocols (`-1`).",
        risk: "Wide-open ingress substantially increases attack surface and enables broad scanning/exploitation of any exposed service.",
        confidenceRationale: "The combination of `0.0.0.0/0` with all ports/protocols is explicit and high-signal.",
        recommendation: "Restrict ingress CIDRs and ports to only what is necessary; prefer private networking and controlled gateways.",
    },
};

export const H1214_TF_SG_EGRESS_WORLD_ALL = {
    id: "H1214_TF_SG_EGRESS_WORLD_ALL",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "MEDIUM",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["aws_security_group", "egress", "cidr_blocks", "0.0.0.0/0"], withinChars: 520 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)egress[\\s\\S]{0,520}\\bcidr_blocks\\s*=\\s*\\[[^\\]]*\"0\\.0\\.0\\.0/0\"[^\\]]*\\][\\s\\S]{0,260}\\b(from_port\\s*=\\s*0\\b|to_port\\s*=\\s*65535\\b|protocol\\s*=\\s*\"-1\")",
        ],
    },
    presentation: { group: "IaC (Big Three)", subgroup: "Terraform", shortLabel: "SG egress wide", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Security Group egress allows all traffic to the internet",
        description: "Terraform security group egress appears to allow all ports/protocols to `0.0.0.0/0`.",
        risk: "Wide egress increases data exfiltration risk and broadens SSRF blast radius if workloads are compromised.",
        confidenceRationale: "The world CIDR combined with all ports/protocols is explicit.",
        recommendation: "Restrict egress where feasible (VPC endpoints, allowlists) and monitor outbound traffic from sensitive workloads.",
    },
};

export const H1215_CF_SG_INGRESS_WORLD_ALL_PORTS = {
    id: "H1215_CF_SG_INGRESS_WORLD_ALL_PORTS",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "HIGH",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["AWS::EC2::SecurityGroup", "SecurityGroupIngress", "CidrIp", "0.0.0.0/0", "FromPort", "ToPort", "IpProtocol"], withinChars: 620 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)CidrIp\\s*:\\s*0\\.0\\.0\\.0/0[\\s\\S]{0,280}(IpProtocol\\s*:\\s*-1\\b|FromPort\\s*:\\s*0\\b|ToPort\\s*:\\s*65535\\b)",
            "(?i)CidrIpv6\\s*:\\s*::/0[\\s\\S]{0,280}(IpProtocol\\s*:\\s*-1\\b|FromPort\\s*:\\s*0\\b|ToPort\\s*:\\s*65535\\b)",
        ],
    },
    presentation: { group: "IaC (Big Three)", subgroup: "CloudFormation", shortLabel: "SG world all ports", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "CloudFormation Security Group ingress allows world on all ports/protocols",
        description: "CloudFormation ingress appears to allow `0.0.0.0/0` (or `::/0`) with all ports or all protocols.",
        risk: "Wide-open ingress drastically increases attack surface and exposure to scanning/exploitation.",
        confidenceRationale: "The world CIDR combined with all ports/protocols is explicit and deterministic.",
        recommendation: "Restrict CIDR ranges and ports to minimum necessary. Prefer private subnets and controlled entry points.",
    },
};

export const H1216_CF_SG_EGRESS_WORLD_ALL = {
    id: "H1216_CF_SG_EGRESS_WORLD_ALL",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "MEDIUM",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["SecurityGroupEgress", "CidrIp", "0.0.0.0/0", "FromPort", "ToPort", "IpProtocol"], withinChars: 620 } },
    detection: {
        type: "REGEX",
        patterns: [
            "(?i)SecurityGroupEgress[\\s\\S]{0,620}(CidrIp\\s*:\\s*0\\.0\\.0\\.0/0|CidrIpv6\\s*:\\s*::/0)[\\s\\S]{0,280}(IpProtocol\\s*:\\s*-1\\b|FromPort\\s*:\\s*0\\b|ToPort\\s*:\\s*65535\\b)",
        ],
    },
    presentation: { group: "IaC (Big Three)", subgroup: "CloudFormation", shortLabel: "Egress wide", maxFindingsPerPR: 2, maxAnnotationsPerPR: 1, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "CloudFormation Security Group egress allows all outbound traffic",
        description: "CloudFormation egress appears to allow all ports/protocols to `0.0.0.0/0` (or `::/0`).",
        risk: "Wide egress can increase data exfiltration and SSRF blast radius in the event of compromise.",
        confidenceRationale: "The pattern is explicit and deterministic when all-ports/all-protocols markers are present.",
        recommendation: "Constrain egress where possible and monitor outbound traffic from sensitive tiers.",
    },
};

export const H1217_TF_S3_VERSIONING_DISABLED = {
    id: "H1217_TF_S3_VERSIONING_DISABLED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "LOW",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["aws_s3_bucket", "versioning", "enabled"], withinChars: 360 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bversioning\\s*\\{[\\s\\S]{0,120}\\benabled\\s*=\\s*false\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Terraform", shortLabel: "S3 versioning off", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "S3 bucket versioning explicitly disabled",
        description: "Terraform config sets S3 versioning `enabled = false`.",
        risk: "Without versioning, recovery from accidental deletion or ransomware-like overwrite becomes harder; this can worsen security incident impact.",
        confidenceRationale: "The setting is explicit and deterministic.",
        recommendation: "Enable versioning for buckets storing important or security-relevant data, and combine with access logs and retention policies.",
    },
};

export const H1218_CF_S3_VERSIONING_SUSPENDED = {
    id: "H1218_CF_S3_VERSIONING_SUSPENDED",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "LOW",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml,json}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["AWS::S3::Bucket", "VersioningConfiguration", "Status"], withinChars: 420 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bVersioningConfiguration\\s*:[\\s\\S]{0,120}\\bStatus\\s*:\\s*Suspended\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "CloudFormation", shortLabel: "S3 versioning suspended", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_SNIPPET_HASH", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "S3 bucket versioning suspended",
        description: "CloudFormation sets S3 versioning status to `Suspended`.",
        risk: "Suspending versioning reduces resilience to accidental deletion/overwrite and can worsen incident recovery.",
        confidenceRationale: "The VersioningConfiguration status is explicit.",
        recommendation: "Enable versioning for critical buckets and ensure retention/backups meet recovery objectives.",
    },
};

export const H1219_TF_S3_FORCE_DESTROY_TRUE = {
    id: "H1219_TF_S3_FORCE_DESTROY_TRUE",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "LOW",
    defaultConfidence: "HIGH",
    appliesTo: { fileGlobs: ["**/*.{tf,tfvars}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "LOW", minimumConfidenceToEmit: "HIGH", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["aws_s3_bucket", "force_destroy"], withinChars: 280 } },
    detection: { type: "REGEX", patterns: ["(?i)\\bforce_destroy\\s*=\\s*true\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Terraform", shortLabel: "force_destroy", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_LINE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "S3 force_destroy enabled",
        description: "Terraform config sets `force_destroy = true` on an S3 bucket.",
        risk: "force_destroy can make destructive actions easier (including mistakes or compromised automation), increasing the blast radius of incidents.",
        confidenceRationale: "The setting is explicit and deterministic.",
        recommendation: "Use force_destroy only for non-production buckets. Add guardrails (separate accounts, approvals, backups/versioning).",
    },
};

export const H1220_K8S_SERVICE_TYPE_LOADBALANCER_OR_NODEPORT = {
    id: "H1220_K8S_SERVICE_TYPE_LOADBALANCER_OR_NODEPORT",
    tier: "TIER_1",
    kind: "WARN",
    category: "Infrastructure-as-Code (Big Three)",
    severity: "MEDIUM",
    defaultConfidence: "MEDIUM",
    appliesTo: { fileGlobs: ["**/*.{yml,yaml}"], scanMode: "DIFF", diffLines: "ADDED_ONLY", maxFileSizeKB: 1024, textOnly: true },
    triggerPolicy: { noise: "MEDIUM", minimumConfidenceToEmit: "MEDIUM", requireSameHunk: true, allowSuppression: true, requireKeywordProximity: { keywords: ["kind: Service", "type:", "LoadBalancer", "NodePort"], withinChars: 420 } },
    detection: { type: "REGEX", patterns: ["(?i)\\btype\\s*:\\s*(LoadBalancer|NodePort)\\b"] },
    presentation: { group: "IaC (Big Three)", subgroup: "Kubernetes", shortLabel: "Service exposed", maxFindingsPerPR: 2, maxAnnotationsPerPR: 0, dedupeStrategy: "BY_FILE", includeInSummary: true, showPreExisting: "SUMMARY_ONLY" },
    explanation: {
        title: "Kubernetes Service exposes workloads via LoadBalancer/NodePort",
        description: "A Service is configured as `LoadBalancer` or `NodePort`.",
        risk: "Externally exposed services are a common source of unintended access. Security depends on network policies, firewalls, and authentication.",
        confidenceRationale: "Service type values are explicit, but exposure depends on cluster/provider configuration (hence WARN).",
        recommendation: "Confirm exposure is intended and protected (auth, TLS, firewall rules). Prefer Ingress/Gateway with controlled policies when possible.",
    },
};

export const WARN_IAC_RULES = [
    H1201_TF_EBS_ENCRYPTION_DISABLED,
    H1202_TF_EC2_ROOT_VOLUME_ENCRYPTION_DISABLED,
    H1203_TF_EBS_SNAPSHOT_ENCRYPTION_DISABLED,
    H1204_CF_EBS_ENCRYPTION_DISABLED,
    H1205_K8S_RUNASUSER_ROOT,
    H1206_K8S_READONLY_ROOT_FS_FALSE,
    H1207_K8S_SECCOMP_UNCONFINED,
    H1208_K8S_CAPABILITIES_ADD_ALL,
    H1209_K8S_CAPABILITIES_ADD_PRIVILEGED_ONES,
    H1210_K8S_HOSTPORT_USED,
    H1211_K8S_AUTOMOUNT_SERVICE_ACCOUNT_TOKEN_TRUE,
    H1212_K8S_IMAGE_TAG_LATEST,
    H1213_TF_SG_INGRESS_WORLD_ALL_PORTS,
    H1214_TF_SG_EGRESS_WORLD_ALL,
    H1215_CF_SG_INGRESS_WORLD_ALL_PORTS,
    H1216_CF_SG_EGRESS_WORLD_ALL,
    H1217_TF_S3_VERSIONING_DISABLED,
    H1218_CF_S3_VERSIONING_SUSPENDED,
    H1219_TF_S3_FORCE_DESTROY_TRUE,
    H1220_K8S_SERVICE_TYPE_LOADBALANCER_OR_NODEPORT,
];
