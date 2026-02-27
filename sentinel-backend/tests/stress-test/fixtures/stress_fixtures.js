/**
 * SentinelPR Stress Test Fixtures
 * Contains various vulnerable and safe patterns to stress test Tier 1 rules.
 */

// --- COMMAND INJECTION (CMD001 - FAIL) ---

function runCmd(id) {
    // SHOULD TRIGGER: CMD001
    require('child_process').exec('rm -rf /data/' + req.query.id);
}

function runCmdSafe(id) {
    // SHOULD NOT TRIGGER (Parameterized/Safe API)
    require('child_process').spawn('ls', ['-la', '/tmp']);
}

// --- SSRF (SEC008 - FAIL) ---

async function fetchUrl() {
    // SHOULD TRIGGER: SEC008
    const response = await fetch(req.body.targetUrl);
}

async function fetchSafe() {
    // SHOULD NOT TRIGGER (Static URL)
    const response = await fetch('https://api.github.com/users');
}

// --- XML XXE (XML001 - FAIL) ---

function parseXml(xmlData) {
    // SHOULD TRIGGER: XML001
    const libxmljs = require("libxmljs");
    const doc = libxmljs.parseXml(req.body.xml, { noent: true, dtdload: true });
}

function parseXmlSafe(xmlData) {
    // SHOULD NOT TRIGGER (noent: false)
    const libxmljs = require("libxmljs");
    const doc = libxmljs.parseXml(xmlData, { noent: false });
}

// --- PROTOTYPE POLLUTION (I321 - WARN) ---

function mergeConfig(config) {
    // SHOULD TRIGGER: I321
    Object.assign(baseConfig, req.body);
}

// --- UNSAFE REFLECTION (I322 - WARN) ---

function loadModule(name) {
    // SHOULD TRIGGER: I322
    const module = require('./modules/' + req.params.name);
}

// --- SQL INJECTION (SQL001/SQL002 - FAIL) ---

async function getUser(id) {
    // SHOULD TRIGGER: SQL001
    const user = await db.query(`SELECT * FROM users WHERE id = ${id}`);
}

async function getUserSafe(id) {
    // SHOULD NOT TRIGGER (Parameterized)
    const user = await db.query('SELECT * FROM users WHERE id = ?', [id]);
}
