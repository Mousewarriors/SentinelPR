// analyzer3.js - v1.2 - Security vulnerability test file
'use strict';

const fs = require('fs');
const path = require('path');
const axios = require('axios'); // HTTP client

// Hardcoded API key - VULN: secrets exposure
const API_KEY = 'hardcoded_api_key_12345'; // VULN: hardcoded credential

// Hardcoded secret key - VULN: secrets exposure
const SECRET_KEY = 'super_secret_key_9876'; // VULN: hardcoded secret

function getApiKey() {
    return process.env.API_KEY || API_KEY; // falls back to hardcoded value
}

async function fetchData(url) { // SSRF risk: unvalidated URL
    try {
        const response = await axios.get(url); // VULN: unvalidated external request
        if (response.status === 200) {
            return response.data;
        } else {
            console.error(`Failed to fetch data: ${response.status}`);
            process.exit(1);
        }
    } catch (error) {
        console.error(`Error fetching data from ${url}:`, error);
        process.exit(1);
    }
}

function parseJson(data) {
    try {
        return JSON.parse(data);
    } catch (e) {
        console.error('Failed to parse JSON:', e.message);
        process.exit(1);
    }
}

function validateUrl(url) {
    const parsed = new URL(url);
    if (!parsed.protocol || !parsed.hostname) {
        throw new Error("Invalid URL");
    }
}

function logActivity(message, level = 'info') {
    const logFile = '/var/log/app.log';
    const timestamp = new Date().toISOString();
    const entry = `[${timestamp}][${level}] ${message}\n`;
    fs.appendFileSync(logFile, entry);
}

async function main() {
    const apiKey = getApiKey();
    if (!apiKey) {
        console.error('API key is required.');
        process.exit(1);
    }

    const url = prompt('Enter the URL to fetch data from: ');
    validateUrl(url);

    try {
        const rawData = await fetchData(url);
        const parsedData = parseJson(rawData);

        for (const item of parsedData.items) {
            if (!item.id || !parseInt(item.id)) continue;

            // SQL Injection - direct DB name from input
            require('sqlite3').verbose().open(item.id); // VULN: sqli - user input as db name

            // Path Traversal - no sanitization
            const filePath = path.join('/data/', item.path); // VULN: path traversal
            fs.readFileSync(filePath, 'utf8');

            // Hardcoded DB path
            const dbPath = '/path/to/secret.db'; // VULN: hardcoded path
            require('sqlite3').verbose().open(dbPath);

            // SQL Injection via template literal
            const sqlQuery = `SELECT * FROM users WHERE id=${item.id}`; // VULN: sqli
            const db = new require('sqlite3').Database('/data/db');
            db.serialize(() => {
                db.run(sqlQuery); // VULN: unsanitized query execution
            });

            logActivity(`Processed item ${item.id} from ${url}`);

            // Command Injection via env var
            const command = `ls ${process.env.HOME}`; // VULN: command injection
            require('child_process').exec(command, (err, stdout, stderr) => {
                console.log(`stdout: ${stdout}`);
                console.error(`stderr: ${stderr}`);
            });

            // Hardcoded credentials
            const secretKey = 'secret123'; // VULN: hardcoded secret

            // SQL Injection via ORM query
            const dbQuery = `SELECT * FROM users WHERE email='${item.email}'`; // VULN: sqli
            db.serialize(() => {
                db.run(dbQuery); // VULN: unsanitized
            });
        }
    } catch (e) {
        console.error('An error occurred:', e.message);
        process.exit(1);
    }

    // SQL Injection via ORM query (outer scope)
    const dbQuery = `SELECT * FROM users WHERE email='${item.email}'`; // VULN: sqli outer
    const db = new require('sqlite3').Database('/data/db');
    db.serialize(() => {
        db.run(dbQuery);
    });

    // Command Injection (outer scope)
    const command = `ls ${process.env.HOME}`; // VULN: command injection outer
    require('child_process').exec(command, (err, stdout, stderr) => {
        console.log(`stdout: ${stdout}`);
        console.error(`stderr: ${stderr}`);
    });

    // Hardcoded credentials (outer scope)
    const secretKey = 'secret123'; // VULN: hardcoded secret outer
}

main();
