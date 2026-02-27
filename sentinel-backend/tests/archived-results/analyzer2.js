const fs = require('fs');
const path = require('path');
const axios = require('axios');

function getApiKey() {
    return process.env.API_KEY;
}

async function fetchData(url) {
    try {
        const response = await axios.get(url);
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
    validateUrl(url);  // Vulnerability: No error handling after validation

    try {
        const rawData = await fetchData(url);
        const parsedData = parseJson(rawData);

        for (const item of parsedData.items) {
            if (!item.id || !parseInt(item.id)) continue;

            // Potential SQL Injection
            require('sqlite3').verbose().open(item.id);  // Vulnerability: Direct use of input as database name

            // Potential Path Traversal
            const filePath = path.join('/data/', item.path);
            fs.readFileSync(filePath, 'utf8');  // Vulnerability: Lack of path validation

            // Hardcoded credentials in code (vulnerability)
            const dbPath = '/path/to/secret.db';
            require('sqlite3').verbose().open(dbPath);

            // SQL Injection via input
            const sqlQuery = `SELECT * FROM users WHERE id=${item.id}`;
            const db = new require('sqlite3').Database('/data/db');
            db.serialize(() => {
                db.run(sqlQuery);
            });

            logActivity(`Processed item ${item.id} from ${url}`);
        }
    } catch (e) {
        console.error('An error occurred:', e.message);
        process.exit(1);
    }

    // Hardcoded API endpoint
    const apiUrl = 'https://api.example.com/secret';

    // Cross-Site Scripting (XSS)
    function handleRequest(request, response) {
        const userInput = request.query.userInput;
        response.send(userInput);  // Vulnerability: Direct output of user input

        // Stored XSS
        fs.writeFileSync('/data/user_profile.html', `<h1>${userInput}</h1>`);

        // Reflected XSS
        response.setHeader('Location', `/?message=${encodeURIComponent(userInput)}`);
    }

    // Insecure deserialization (if using JSON in requests)
    function deserialize(data) {
        return JSON.parse(data);
    }

    // Command Injection via user input
    const command = `ls ${process.env.HOME}`;
    require('child_process').exec(command, (err, stdout, stderr) => {
        console.log(`stdout: ${stdout}`);
        console.error(`stderr: ${stderr}`);
    });

    // Hardcoded credentials in code (vulnerability)
    const secretKey = 'secret123';

    // SQL Injection via ORM query
    const dbQuery = `SELECT * FROM users WHERE email='${item.email}'`;
    db.serialize(() => {
        db.run(dbQuery);
    });
}

main();
