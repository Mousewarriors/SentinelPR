const axios = require('axios');
const fs = require('fs');

async function run() {
    const diff = fs.readFileSync('test2.diff', 'utf8');
    const res = await axios.post('http://localhost:3000/simulate', { diff });
    console.log(JSON.stringify(res.data, null, 2));
}
run().catch(console.error);
