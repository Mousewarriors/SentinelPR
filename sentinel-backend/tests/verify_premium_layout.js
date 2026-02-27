import axios from 'axios';

const diff = `+++ b/analysis.py
+import subprocess
+user_input = "test"
+subprocess.run(["ls", user_input])
+query = "SELECT * FROM users WHERE id = " + user_input
+db.execute(query)
+path = "/tmp/" + user_input
+open(path, "r")
`;

async function test() {
    try {
        const response = await axios.post('http://localhost:3000/simulate', { diff });
        console.log("=== SUMMARY MARKDOWN ===");
        console.log(response.data.summaryMarkdown);
    } catch (error) {
        console.error("Error during simulation:", error.message);
        if (error.response) console.error(error.response.data);
    }
}

test();
