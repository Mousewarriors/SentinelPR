# 🔐 SentinelPR

**Automated Secure Code Review for Modern Engineering Teams.**

SentinelPR is a high-performance GitHub App that scans every Pull Request for security vulnerabilities, logic flaws, and sensitive data leaks. By combining lightning-fast static analysis with deep AI-powered semantic audits, Sentinel provides a robust defense against "day-zero" security regressions.

---

## 🔥 Key Features

- **🚀 Dual-Tier Analysis Engine**
  - **Tier 1 (Static)**: 800+ optimized security rules targeting secrets, dangerous API sinks, and IaC misconfigurations.
  - **Tier 2 (AI Semantic)**: Triple-pass audit using LLMs (Gemini/Ollama) to detect complex logical vulnerabilities that static tools miss.
- **📊 Professional Reporting**: Rich markdown summaries posted directly to your GitHub Check Runs, complete with severity levels, impact statements, and remediation guides.
- **🛡️ Secure by Design**: Cryptographic webhook verification (HMAC-SHA256) and minimal permission requirements.
- **📉 Noise Reduction**: Intelligent deduplication and high-confidence filtering ensure developers only see findings that matter.

---

## 🏗️ How It Works

SentinelPR follows a sophisticated multi-stage pipeline:

1.  **Ingestion**: Receives GitHub webhooks (Pull Request events).
2.  **Verification**: Validates authenticity using HMAC-SHA256 signatures.
3.  **Tier 1 Scan**: Executes pattern-matching rules for immediate identification of known bad patterns.
4.  **Tier 2 Audit**: Pipes the code diff to an AI engine for a deep semantic "triple-pass" security review.
5.  **Reporting**: Consolidates findings and updates the GitHub Check Run status.

For more technical details, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## 🛠️ Setup & Installation

### Prerequisites
- [Node.js](https://nodejs.org/) (v18+ recommended)
- A GitHub App with `checks:write` and `pull_requests:read` permissions.

### Quick Start

1.  **Clone & Install**:
    ```bash
    git clone https://github.com/Mousewarriors/SentinelPR.git
    cd SentinelPR/sentinel-backend
    npm install
    ```

2.  **Configure Environment**:
    Create a `.env` file based on `.env.example`:
    ```ini
    PORT=3000
    GITHUB_APP_ID=your_app_id
    GITHUB_WEBHOOK_SECRET=your_webhook_secret
    GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."
    GEMINI_API_KEY=your_gemini_key
    ```

3.  **Run Service**:
    ```bash
    npm start
    ```

---

## 🛡️ Security & Privacy

SentinelPR is built with a **"Read-Only, Secure-First"** philosophy:
- **No Persistence**: Diff data is processed in-memory and never stored long-term.
- **Minimal Scopes**: Only requires access to the metadata needed to perform the scan.
- **Encrypted Channels**: Supports full HMAC verification for all incoming signals.

---

## 📄 License
SentinelPR is licensed under the [ISC License](./LICENSE). 

---

*Built with ❤️ for secure engineering.*
