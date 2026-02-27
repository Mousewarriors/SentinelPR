# Sentinel PR Backend - Phase 2 (Secure)

This is a backend service designed to receive and log GitHub webhook events securely.

## Phase 2: Security Features
The endpoint is now secured using **GitHub Signature Verification (HMAC-SHA256)**. This ensures that only requests originating from GitHub (and sharing your secret) are processed.

### How Verification Works
1. When GitHub sends a webhook, it computes a hash of the request body using your **Secret** as the key.
2. GitHub sends this hash in the `X-Hub-Signature-256` header.
3. Our server receives the request, takes the raw body, and computes its own hash using the same `GITHUB_WEBHOOK_SECRET`.
4. We use `crypto.timingSafeEqual` to compare our hash with GitHub's. If they match, the request is authentic.

## Prerequisites
- [Node.js](https://nodejs.org/) (v14 or later recommended)

## Setup and Running

1. **Navigate to the backend directory:**
   ```bash
   cd "d:\Sentinel setup\sentinel-backend"
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure the Secret:**
   Open the `.env` file and set your `GITHUB_WEBHOOK_SECRET`:
   ```text
   GITHUB_WEBHOOK_SECRET=super-secret-key
   ```

4. **Start the server:**
   ```bash
   node server.js
   ```

## Testing the Secured Webhook

Testing now requires generating a valid signature. You can use the following PowerShell script to test locally:

```powershell
# 1. Define your secret (must match .env)
$secret = "super-secret-key"

# 2. Define the payload
$body = @{
    action = "opened"
    pull_request = @{ number = 101 }
    repository = @{ full_name = "awesome-org/awesome-repo" }
} | ConvertTo-Json -Compress

# 3. Generate HMAC-SHA256 signature
$hmacsha = New-Object System.Security.Cryptography.HMACSHA256
$hmacsha.Key = [Text.Encoding]::ASCII.GetBytes($secret)
$signatureBytes = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($body))
$signature = "sha256=" + [System.BitConverter]::ToString($signatureBytes).Replace("-", "").ToLower()

# 4. Send the request
Invoke-RestMethod -Uri http://localhost:3000/github/webhook `
    -Method Post `
    -Headers @{
        "X-GitHub-Event" = "pull_request"
        "X-Hub-Signature-256" = $signature
    } `
    -Body $body `
    -ContentType "application/json"
```

## Expected Output
If the signature is correct, the server logs:
`Signature verified successfully.`

If the signature is missing or incorrect, the server returns **401 Unauthorized** and logs:
`Verification failed: Signature mismatch.`
