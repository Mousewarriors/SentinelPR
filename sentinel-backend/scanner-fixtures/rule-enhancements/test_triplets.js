// --- 1. Engine Filter Test ---
// FAIL: S004 (if in code)
const tokenCode = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";

// SAFE: S004 (if in comment)
// const tokenComment = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";

// --- 2. Entropy Gate 2.0 Test ---
// FAIL: W101 (Short entropy > 4.1)
const tinyKey = "A1b2C3d4E5f6G7h8I9j0K1l2"; // Length 24, high entropy

// SAFE: W101 (Short entropy < 4.1)
const fakeKey = "ThisIsJustALongerString"; // Length 24, low entropy

// --- 3. Taint correlation Test ---
// FAIL: PATH001 (User input -> Sink)
const userInput = req.query.path;
fs.readFileSync(userInput);

// SAFE: PATH001 (Guarded)
const safePath = path.basename(req.query.path);
fs.readFileSync(safePath);

// --- 4. New FAIL rules ---
// FAIL: SSL001 (Triggered by IS_PROD_CONTEXT in verify script simulation)
const client = axios.create({ rejectUnauthorized: false });

// FAIL: DESER001
const data = msgpack.deserialize(req.body);

// --- 5. Correlation Layer ---
// WARN: M001 (Secret + Logging)
const apiKeyLabel = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
console.log("The secret token is:", apiKeyLabel); // Triggers L801 and W101
