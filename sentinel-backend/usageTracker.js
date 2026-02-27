import fs from "fs";
import path from "path";

const USAGE_FILE = path.join(process.cwd(), ".usage_usage.json");

const TIERS = {
    FREE: { limit: 9999, price: 0 },
    PRO: { limit: 50, price: 59 },
    ENTERPRISE: { limit: 200, price: 149 } // (Note: £149 in current plans)
};

/**
 * Basic Persistence for usage tracking.
 * In production, move this to Redis or PostgreSQL.
 */
let usageData = {};
try {
    if (fs.existsSync(USAGE_FILE)) {
        usageData = JSON.parse(fs.readFileSync(USAGE_FILE, "utf8"));
    }
} catch (e) {
    usageData = {};
}

function save() {
    fs.writeFileSync(USAGE_FILE, JSON.stringify(usageData, null, 2));
}

export function checkUsage(installationId) {
    const currentMonth = new Date().toISOString().slice(0, 7); // "2024-03"

    if (!usageData[installationId]) {
        usageData[installationId] = {
            tier: "FREE",
            monthlyCounts: {}
        };
    }

    const inst = usageData[installationId];
    if (!inst.monthlyCounts[currentMonth]) {
        inst.monthlyCounts[currentMonth] = 0;
    }

    const tierLimit = TIERS[inst.tier].limit;
    const currentCount = inst.monthlyCounts[currentMonth];

    return {
        allowed: currentCount < tierLimit,
        current: currentCount,
        limit: tierLimit,
        tier: inst.tier
    };
}

export function incrementUsage(installationId) {
    const currentMonth = new Date().toISOString().slice(0, 7);
    usageData[installationId].monthlyCounts[currentMonth]++;
    save();
}

/**
 * Admin function to upgrade a repo
 */
export function setTier(installationId, tierName) {
    if (TIERS[tierName]) {
        if (!usageData[installationId]) usageData[installationId] = { monthlyCounts: {} };
        usageData[installationId].tier = tierName;
        save();
        return true;
    }
    return false;
}
