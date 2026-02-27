/**
 * Intentionally vulnerable demo app (NON-DESTRUCTIVE) for testing code analyzers.
 * Vulnerabilities included:
 *  1) IDOR (Insecure Direct Object Reference)
 *  2) SSRF (Server-Side Request Forgery)
 *  3) SQL Injection
 *  4) Reflected XSS
 *  5) Path Traversal (LFI-style file read)
 *
 * npm i express node-fetch sqlite3
 * node vulnerable-demo.js
 */

const express = require("express");
const fetch = require("node-fetch"); // v2 style import (works in many setups)
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());

// ----- Simple auth simulation (NOT REAL SECURITY) -----
function fakeAuth(req, res, next) {
    // In a real SaaS app, you'd validate a session/JWT and set req.user properly.
    // We'll simulate a logged-in user via header: x-user-id
    req.user = { id: req.header("x-user-id") || "user-1" };
    next();
}
app.use(fakeAuth);

// ----- In-memory SQLite DB -----
const db = new sqlite3.Database(":memory:");
db.serialize(() => {
    db.run("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT)");
    db.run("CREATE TABLE invoices (id TEXT PRIMARY KEY, ownerId TEXT, amount INTEGER)");
    db.run("INSERT INTO users VALUES ('user-1','alice@example.com'), ('user-2','bob@example.com')");
    db.run("INSERT INTO invoices VALUES ('inv-100','user-1',500), ('inv-200','user-2',900)");
});

/**
 * 1) IDOR
 * VULNERABLE: Fetching an invoice by ID without verifying it belongs to the authenticated user.
 * Detectable patterns: direct object reference by ID + missing authorization check.
 */
app.get("/api/invoices/:invoiceId", (req, res) => {
    const { invoiceId } = req.params;

    // ❌ Vulnerable: no check that invoice.ownerId === req.user.id
    db.get("SELECT * FROM invoices WHERE id = ?", [invoiceId], (err, row) => {
        if (err) return res.status(500).json({ error: "db error" });
        if (!row) return res.status(404).json({ error: "not found" });
        return res.json(row);
    });
});

/**
 * 2) SSRF
 * VULNERABLE: Server fetches a user-controlled URL.
 * Non-destructive: returns only status + first 200 chars of response body.
 * Detectable patterns: fetch(urlFromUser) / axios.get(userInput) without allowlist.
 */
app.get("/api/fetch", async (req, res) => {
    const url = req.query.url;

    if (!url) return res.status(400).json({ error: "missing url" });

    try {
        // ❌ Vulnerable: user controls the full URL (can target internal metadata services, localhost, etc.)
        const r = await fetch(url, { method: "GET" });
        const text = await r.text();
        res.json({
            fetched: url,
            status: r.status,
            preview: text.slice(0, 200), // keep it small; still demonstrates the issue
        });
    } catch (e) {
        res.status(502).json({ error: "fetch failed", details: String(e.message || e) });
    }
});

/**
 * 3) SQL Injection
 * VULNERABLE: String concatenation in SQL query.
 * Non-destructive: a read-only search endpoint.
 * Detectable patterns: "SELECT ... WHERE ... = '" + userInput + "'"
 */
app.get("/api/users/search", (req, res) => {
    const email = req.query.email || "";

    // ❌ Vulnerable: SQL injection via concatenation
    const sql = "SELECT id, email FROM users WHERE email = '" + email + "'";

    db.all(sql, (err, rows) => {
        if (err) return res.status(500).json({ error: "db error", details: err.message });
        res.json({ query: sql, results: rows });
    });
});

/**
 * 4) Reflected XSS
 * VULNERABLE: Reflecting unescaped input into HTML.
 * Non-destructive: just returns HTML.
 * Detectable patterns: res.send(`<html>...${userInput}...</html>`) without escaping.
 */
app.get("/help", (req, res) => {
    const q = req.query.q || "";

    // ❌ Vulnerable: reflected XSS in HTML response
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`
    <!doctype html>
    <html>
      <body>
        <h1>Help</h1>
        <p>You searched for: ${q}</p>
      </body>
    </html>
  `);
});

/**
 * 5) Path Traversal (Local File Read)
 * VULNERABLE: User-controlled path joined to a base directory without normalization/allowlist.
 * Non-destructive: reads a file and returns it (read-only), but can expose sensitive files if reachable.
 * Detectable patterns: fs.readFile(base + userPath) / path.join(base, userInput) without checks.
 */
app.get("/api/files", (req, res) => {
    const name = req.query.name || "example.txt";

    const baseDir = path.join(__dirname, "public-files");
    const filePath = path.join(baseDir, name);

    // ❌ Vulnerable: attacker can use ../ to escape baseDir
    fs.readFile(filePath, "utf8", (err, data) => {
        if (err) return res.status(404).json({ error: "file not found", tried: filePath });
        res.json({ file: name, contentsPreview: data.slice(0, 500) });
    });
});

app.get("/", (req, res) => res.send("Vulnerable demo app running. See routes in code."));
app.listen(3000, () => console.log("Listening on http://localhost:3000"));