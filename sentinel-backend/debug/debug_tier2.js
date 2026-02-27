import "dotenv/config";
import { runTier2Analysis } from "./tier2Analyzer.js";
import fs from "fs";
import path from "path";

async function test() {
    const diff = fs.readFileSync('test3.js', 'utf8');
    console.log("Running EXHAUSTIVE analysis on test3.js...");
    const result = await runTier2Analysis("test", "test", 1, "sha-123", diff);
    console.log("\n--- RESULT ---");
    console.log(JSON.stringify(result, null, 2));
}

test();
