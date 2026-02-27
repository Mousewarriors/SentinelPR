/**
 * test4.js — The "Subtle" Suite
 * Only contains issues missed in the previous exhaustive run.
 */
const express = require("express");
const crypto = require("crypto");
const app = express();
app.use(express.json());

// 1. INSECURE CORS (Logical Misconfig)
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*"); // Wildcard
    res.setHeader("Access-Control-Allow-Credentials", "true"); // Incompatible with wildcard in strict browsers, but risky
    next();
});

// 2. CSRF (Missing Protection)
// This sensitive state-change has no CSRF tokens or SameSite cookie checks.
const balances = { "user-1": 1000 };
app.post("/api/transfer", (req, res) => {
    const { to, amount } = req.body;
    const from = req.header("x-user-id");
    balances[from] -= amount;
    console.log(`Transferred ${amount} to ${to}`);
    res.json({ success: true });
});

// 3. PREDICTABLE TOKENS (Weak PRNG)
app.post("/api/password-reset", (req, res) => {
    // ❌ Vulnerable: Math.random() is not cryptographically secure
    const token = Math.random().toString(36).substring(2);
    res.json({ msg: "Reset link sent", debug_token: token });
});

// 4. SENSITIVE DATA EXPOSURE (Verbose Errors)
const MASTER_KEY = "super-secret-backend-key-123";
app.get("/api/debug", (req, res) => {
    try {
        throw new Error("Connection failed");
    } catch (e) {
        // ❌ Vulnerable: Leakage of stack trace AND internal master key
        res.status(500).json({
            status: "error",
            stack: e.stack,
            internal_code: MASTER_KEY
        });
    }
});

app.listen(3000);
