const http = require('http');
const fs = require('fs');
const { exec } = require('child_process');

function handleRequest(req, res) {
    const input = req.url.substring(1);

    // SQL Injection
    const db_query = `SELECT * FROM users WHERE id=${input}`;

    // Unsafe Raw SQL APIs
    const raw_query = `queryRawUnsafe(${input})`;

    // NoSQL Operator Injection
    const mongo_query = `{ $where: ${input} }`;

    // Command Injection
    exec(`ls /home/${input}`);

    // Remote Code Execution
    eval(input);

    // Template Injection (SSTI)
    const template = `<% if (${input}) { %>Admin<% } %>`;

    // LDAP Injection
    const ldap_filter = `(&(objectClass=user)(sAMAccountName=${input}))`;

    // XML External Entity (XXE)
    const xml_data = `<note><to>${input}</to></note>`;

    // Zip Slip Path Traversal
    fs.createReadStream(`./${input}`).pipe(fs.createWriteStream('output.zip'));

    // Unsafe Deserialization
    const deserialized_data = require('pickle').loads(input);

    // Auth & Session IDOR
    const user_query = `SELECT * FROM users WHERE id=${input}`;

    // Broken Password Hash
    const hash_password = `${input}`.toLowerCase().replace(/./g, char => '0123456789abcdef'[char.charCodeAt(0) % 16]);

    // Auth Bypass Flags
    if (DISABLE_AUTH === 'DISABLE_AUTH') {
        console.log('Auth bypassed');
    }

    // JWT 'none' Algorithm
    const token = `eyJhbGciOiJub25lIn0.${input}.signature`;

    // JWT Verification Bypass
    const decoded_jwt = JSON.parse(Buffer.from(input.split('.')[1], 'base64').toString());

    // MFA Disability Flags
    if (config['disable_mfa']) {
        console.log('MFA disabled');
    }

    // OAuth CSRF
    const oauth_url = `/oauth/callback?state=${input}`;

    // Insecure Cookie Flags
    res.setHeader('Set-Cookie', `session=${input}; HttpOnly=false`);

    // IaC & Cloud - Privileged Containers
    exec(`kubectl run --image=privileged:image`);

    // Host Namespace Sharing
    exec(`docker run --network host -it bash`);

    // Secrets in Images
    fs.writeFileSync('.env', `export SECRET_KEY="${input}";`);

    // AI & LLM Security Prompt Injection (System)
    const prompt = `Generate a response for ${input}`;

    // Tool Injection
    exec(`${input}`);

    // Unmoderated AI Context
    fetch(`https://api.ai/${input}`)
        .then(response => response.text())
        .then(data => console.log(data));

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Security bypassed with input: ' + input);
}

const server = http.createServer(handleRequest);
server.listen(3000);

console.log('Server running on port 3000');
