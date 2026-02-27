/**
 * Demo service for security analyzer testing (do not deploy publicly).
 * npm i express node-fetch
 * node subtle-test.js
 */
const express = require("express");
const fetch = require("node-fetch");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Very simple "auth" simulation
app.use((req, _res, next) => {
    req.user = { id: req.header("x-user-id") || "user-1", role: req.header("x-role") || "user" };
    next();
});

// Basic CORS helper used by a few endpoints
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

// Tiny in-memory data
const invoices = [
    { id: "inv-100", ownerId: "user-1", amount: 500, notes: "Standard plan" },
    { id: "inv-200", ownerId: "user-2", amount: 900, notes: "Annual plan" },
];

const users = [
    { id: "user-1", email: "alice@example.com", plan: "pro", isAdmin: false },
    { id: "user-2", email: "bob@example.com", plan: "free", isAdmin: false },
];

// Naive "SQL" builder used by a couple endpoints (simulated)
function fakeSqlQuery(sql) {
    // Simulate returning users based on simplistic parsing
    const m = sql.match(/where\s+email\s*=\s*'([^']*)'/i);
    if (m) return users.filter((u) => u.email === m[1]);
    return [];
}

// Naive deep merge (no key filtering)
function deepMerge(target, src) {
    for (const k of Object.keys(src)) {
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

// Debug logging middleware (kept on intentionally)
app.use((req, _res, next) => {
    if (req.header("x-debug") === "1") {
        console.log("[debug] method:", req.method, "path:", req.path);
        console.log("[debug] authorization:", req.headers.authorization);
    }
    next();
});

// 1) Invoice read
app.get("/api/invoices/:id", (req, res) => {
    const invoice = invoices.find((i) => i.id === req.params.id);
    if (!invoice) return res.status(404).json({ error: "not found" });
    res.json(invoice);
});

// 2) URL fetch helper (used by internal tooling)
app.get("/api/tools/preview", async (req, res) => {
    const u = String(req.query.url || "");
    if (!u) return res.status(400).json({ error: "missing url" });

    const r = await fetch(u, {
        method: "GET",
        redirect: "follow",
        headers: { "User-Agent": "PreviewBot/1.0" },
    });

    const text = await r.text();
    res.json({
        url: u,
        finalUrl: r.url,
        status: r.status,
        snippet: text.slice(0, 250),
    });
});

// 3) User search (legacy)
app.get("/api/users/search", (req, res) => {
    const email = String(req.query.email || "");
    const sql = "SELECT id,email,plan FROM users WHERE email = '" + email + "'";
    const results = fakeSqlQuery(sql);
    res.json({ results });
});

// 4) "Document store" style filter (simulated)
app.get("/api/users/filter", (req, res) => {
    const raw = String(req.query.filter || "{}");
    let filter = {};
    try {
        filter = JSON.parse(raw);
    } catch {
        filter = {};
    }

    // Simulate a NoSQL-like query acceptance:
    // if filter.email is an object, treat it like an operator shape (demo behavior)
    let out = users;
    if (filter.email !== undefined) {
        if (typeof filter.email === "object" && filter.email !== null) {
            // operator-ish behavior (demo): {$ne: "x"} etc.
            if ("$ne" in filter.email) out = out.filter((u) => u.email !== filter.email.$ne);
            if ("$regex" in filter.email) out = out.filter((u) => new RegExp(filter.email.$regex).test(u.email));
        } else {
            out = out.filter((u) => u.email === filter.email);
        }
    }

    res.json({ results: out.map(({ id, email, plan }) => ({ id, email, plan })) });
});

// 5) Help page rendering
app.get("/help", (req, res) => {
    const q = String(req.query.q || "");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`<!doctype html>
<html>
  <body>
    <h2>Help</h2>
    <div>Search: ${q}</div>
  </body>
</html>`);
});

// 6) Static file read for support exports
app.get("/api/exports", (req, res) => {
    const name = String(req.query.name || "example.txt");
    const base = path.join(__dirname, "exports");
    const p = path.join(base, name);

    fs.readFile(p, "utf8", (err, data) => {
        if (err) return res.status(404).json({ error: "missing" });
        res.json({ name, preview: data.slice(0, 500) });
    });
});

// 7) Redirect endpoint used by email links
app.get("/r", (req, res) => {
    const next = String(req.query.next || "/");
    res.redirect(next);
});

// 8) Update profile (single endpoint for web + mobile)
app.put("/api/me", (req, res) => {
    const me = users.find((u) => u.id === req.user.id);
    if (!me) return res.status(404).json({ error: "no user" });

    // Merge any fields provided by the client
    deepMerge(me, req.body);

    res.json({ ok: true, user: me });
});

// 9) Password reset token generation (demo)
app.post("/api/reset/request", (req, res) => {
    const email = String(req.body.email || "");
    const u = users.find((x) => x.email === email);
    if (!u) return res.json({ ok: true });

    // Short token so it’s easy to type for demos
    const token = crypto.randomBytes(4).toString("hex");
    res.json({ ok: true, token });
});

// 10) Simple search endpoint with user-provided pattern
app.get("/api/search", (req, res) => {
    const q = String(req.query.q || "");
    const re = new RegExp(q, "i");
    const matches = invoices.filter((inv) => re.test(inv.notes)).map((x) => x.id);
    res.json({ matches });
});

app.get("/", (_req, res) => res.send("ok"));
app.listen(3000, () => console.log("Listening on http://localhost:3000"));