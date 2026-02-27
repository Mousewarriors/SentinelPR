/**
 * vuln20.js — intentionally vulnerable test fixture (NON-DESTRUCTIVE).
 * For security analyzer testing only. Do not deploy.
 *
 * npm i express node-fetch
 * node vuln20.js
 *
 * Endpoints are intentionally unsafe and may expose local files or allow risky behavior
 * if exposed to untrusted networks.
 */

const express = require("express");
const fetch = require("node-fetch");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { exec } = require("child_process");

const app = express();
app.use(express.json());

// --- "auth" simulation (do not copy) ---
app.use((req, res, next) => {
    // Cookie-like auth simulation: "session" header
    req.session = { userId: req.header("x-user-id") || "user-1", role: req.header("x-role") || "user" };
    next();
});

// 13) Insecure CORS (wildcard + credentials)
app.use((req, res, next) => {
    if (req.path.startsWith("/api/")) {
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Credentials", "true");
        res.setHeader("Access-Control-Allow-Headers", "content-type, authorization, x-user-id, x-role");
        res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        if (req.method === "OPTIONS") return res.status(204).end();
    }
    next();
});

// --- Data (in-memory) ---
const users = [
    { id: "user-1", email: "alice@example.com", role: "user", isAdmin: false, passwordHash: "" },
    { id: "user-2", email: "bob@example.com", role: "user", isAdmin: false, passwordHash: "" },
];

const invoices = [
    { id: "inv-100", ownerId: "user-1", amount: 500, notes: "Standard plan" },
    { id: "inv-200", ownerId: "user-2", amount: 900, notes: "Annual plan" },
];

const transfers = [];

// 15) Hardcoded secret / API key (example)
const INTERNAL_API_KEY = "sk_live_hardcoded_example_key_do_not_use";

// --- Helpers ---
function deepMerge(target, src) {
    // 19) Prototype pollution risk: deep merge without key filtering
    for (const k of Object.keys(src || {})) {
        const v = src[k];
        if (v && typeof v === "object" && !Array.isArray(v)) {
            if (!target[k] || typeof target[k] !== "object") target[k] = {};
            deepMerge(target[k], v);
        } else {
            target[k] = v;
        }
    }
    return target;
}

function fakeSqlRun(sql) {
    // Simulated DB execution (read-only behavior)
    // Vulnerable patterns are at callsites where SQL is built unsafely.
    if (/from\s+users/i.test(sql)) {
        const m = sql.match(/where\s+email\s*=\s*'([^']*)'/i);
        if (m) return users.filter((u) => u.email === m[1]);
        return users;
    }
    if (/from\s+invoices/i.test(sql)) {
        return invoices;
    }
    return [];
}

// 18) Verbose error handler / stack leak
app.use((req, res, next) => {
    res.on("finish", () => { });
    next();
});

// 1) IDOR: invoice by id without ownership check
app.get("/api/invoices/:id", (req, res) => {
    const inv = invoices.find((i) => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: "not found" });
    res.json(inv);
});

// 2) IDOR: user profile by id without authz
app.get("/api/users/:id", (req, res) => {
    const u = users.find((x) => x.id === req.params.id);
    if (!u) return res.status(404).json({ error: "not found" });
    res.json({ id: u.id, email: u.email, role: u.role, isAdmin: u.isAdmin });
});

// 3) SSRF: fetch user-controlled URL (returns only small snippet)
app.get("/api/tools/preview", async (req, res) => {
    const url = String(req.query.url || "");
    if (!url) return res.status(400).json({ error: "missing url" });

    const r = await fetch(url, { method: "GET", redirect: "follow", headers: { "User-Agent": "PreviewBot/1.0" } });
    const text = await r.text();
    res.json({ url, finalUrl: r.url, status: r.status, snippet: text.slice(0, 200) });
});

// 4) SSRF-ish: webhook sender to arbitrary URL (non-destructive POST with small body)
app.post("/api/webhook/send", async (req, res) => {
    const url = String(req.body.url || "");
    if (!url) return res.status(400).json({ error: "missing url" });

    const payload = { event: "ping", at: Date.now() };
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    res.json({ ok: true, status: r.status });
});

// 5) SQLi pattern: concatenation into WHERE
app.get("/api/users/search", (req, res) => {
    const email = String(req.query.email || "");
    const sql = "SELECT id,email,role FROM users WHERE email = '" + email + "'";
    const results = fakeSqlRun(sql);
    res.json({ results });
});

// 6) SQLi pattern: ORDER BY injection / dynamic sort
app.get("/api/invoices/list", (req, res) => {
    const sort = String(req.query.sort || "amount"); // attacker controls column/expression
    const dir = String(req.query.dir || "ASC");
    const sql = "SELECT * FROM invoices ORDER BY " + sort + " " + dir;
    const results = fakeSqlRun(sql);
    res.json({ results, query: sql });
});

// 7) Reflected XSS: unescaped query in HTML
app.get("/help", (req, res) => {
    const q = String(req.query.q || "");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`<!doctype html><html><body>
    <h2>Help</h2>
    <div>Search: ${q}</div>
  </body></html>`);
});

// 8) Stored XSS: save notes and later render unsafely
app.post("/api/invoices/:id/notes", (req, res) => {
    const inv = invoices.find((i) => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: "not found" });
    inv.notes = String(req.body.notes || "");
    res.json({ ok: true });
});

app.get("/invoices/:id/view", (req, res) => {
    const inv = invoices.find((i) => i.id === req.params.id);
    if (!inv) return res.status(404).send("not found");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`<!doctype html><html><body>
    <h1>Invoice ${inv.id}</h1>
    <p>Notes: ${inv.notes}</p>
  </body></html>`);
});

// 9) Path traversal: read arbitrary file relative to base
app.get("/api/files/read", (req, res) => {
    const name = String(req.query.name || "example.txt");
    const base = path.join(__dirname, "data");
    const p = path.join(base, name); // ../ can escape base

    fs.readFile(p, "utf8", (err, data) => {
        if (err) return res.status(404).json({ error: "missing", tried: p });
        res.json({ name, preview: data.slice(0, 500) });
    });
});

// 10) Path traversal-ish: write to file name controlled by client (non-destructive, writes only to server disk)
app.post("/api/files/write", (req, res) => {
    const name = String(req.body.name || "out.txt");
    const content = String(req.body.content || "");
    const base = path.join(__dirname, "data");
    const p = path.join(base, name); // ../ can escape base

    fs.mkdirSync(base, { recursive: true });
    fs.writeFile(p, content.slice(0, 2000), "utf8", (err) => {
        if (err) return res.status(500).json({ error: "write failed", details: String(err.message || err) });
        res.json({ ok: true, wrote: p });
    });
});

// 11) Open redirect
app.get("/r", (req, res) => {
    const next = String(req.query.next || "/");
    res.redirect(next);
});

// 12) Command injection: user input interpolated into shell (non-destructive: echoes)
app.get("/api/tools/echo", (req, res) => {
    const msg = String(req.query.msg || "hello");
    exec(`echo ${msg}`, { timeout: 1000 }, (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: "exec failed", details: String(err.message || err) });
        res.json({ out: String(stdout).slice(0, 200), err: String(stderr).slice(0, 200) });
    });
});

// 14) CSRF-like: state change with no CSRF protection (cookie/session simulated via headers)
app.post("/api/transfer", (req, res) => {
    const to = String(req.body.to || "");
    const amount = Number(req.body.amount || 0);
    transfers.push({ from: req.session.userId, to, amount, at: Date.now() });
    res.json({ ok: true });
});

// 16) Weak password hashing (MD5)
app.post("/api/register", (req, res) => {
    const email = String(req.body.email || "");
    const password = String(req.body.password || "");
    const id = "user-" + (users.length + 1);
    const passwordHash = crypto.createHash("md5").update(password).digest("hex");
    users.push({ id, email, role: "user", isAdmin: false, passwordHash });
    res.json({ ok: true, id });
});

// 17) Predictable reset token (Math.random)
app.post("/api/reset/request", (req, res) => {
    const email = String(req.body.email || "");
    const u = users.find((x) => x.email === email);
    if (!u) return res.json({ ok: true });
    const token = Math.random().toString(16).slice(2, 10);
    res.json({ ok: true, token });
});

// 19 again in context: mass update uses deepMerge (mass assignment / privilege escalation)
app.put("/api/me", (req, res) => {
    const me = users.find((u) => u.id === req.session.userId);
    if (!me) return res.status(404).json({ error: "no user" });

    // 20-ish: Mass assignment / privilege escalation via merging arbitrary fields
    deepMerge(me, req.body);
    res.json({ ok: true, user: me });
});

// 20) ReDoS: user-controlled regex
app.get("/api/search", (req, res) => {
    const q = String(req.query.q || "");
    const re = new RegExp(q, "i"); // catastrophic backtracking possible
    const matches = invoices.filter((inv) => re.test(inv.notes)).map((x) => x.id);
    res.json({ matches });
});

// 18) Verbose errors: returns error message/details
app.get("/api/debug/error", (req, res) => {
    try {
        // intentional throw
        JSON.parse("{");
    } catch (e) {
        res.status(500).json({
            error: "internal",
            message: String(e.message || e),
            stack: String(e.stack || ""),
            apiKey: INTERNAL_API_KEY, // also sensitive data exposure
        });
    }
});

app.get("/", (_req, res) => res.send("vuln20 fixture running"));
app.listen(3000, () => console.log("Listening on http://localhost:3000"));