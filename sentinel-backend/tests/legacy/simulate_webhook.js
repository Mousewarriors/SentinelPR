import crypto from "crypto";
import axios from "axios";

const secret = "12f767d77e410b7285859d931fd9649f8ce5eb47cf01013f9eeb0a4d15471bbb";
const payload = {
    action: "opened",
    pull_request: {
        number: 1,
        head: {
            sha: "test-sha-" + Date.now()
        }
    },
    repository: {
        full_name: "test-owner/test-repo"
    },
    installation: {
        id: 12345
    }
};

const body = JSON.stringify(payload);
const hmac = crypto.createHmac("sha256", secret);
const signature = "sha256=" + hmac.update(body).digest("hex");

async function run() {
    try {
        const res = await axios.post("http://localhost:3000/github/webhook", body, {
            headers: {
                "Content-Type": "application/json",
                "x-github-event": "pull_request",
                "x-hub-signature-256": signature
            }
        });
        console.log("Response:", res.data);
    } catch (error) {
        console.error("Error:", error.message);
    }
}

run();
