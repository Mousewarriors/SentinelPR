const http = require('http');
const fs = require('fs');

function handleRequest(req, res) {
    const input = req.url.substring(1);

    const db_query = `SELECT * FROM users WHERE id=${input}`;

    require('child_process').exec(`ls /home/${input}`);

    fs.readFile('/data/' + input, (err, data) => {
        if (!err) res.end(data);
    });

    eval(input);

    const template = `<%= ${input} %>`;

    const ldap_filter = `(uid=${input})`;

    fs.readFile('/data/config.xml', (err, data) => {
        if (!err) res.end(data);
    });

    try {
        const deserialized_data = require('pickle').loads(input);
    } catch (e) { }

    res.setHeader("Set-Cookie", `session=${input}; HttpOnly=false`);

    const oauthUrl = `/oauth/callback?state=${input}`;
}

http.createServer(handleRequest).listen(8080);
