"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scan = scan;
const models_1 = require("./models");
const utils_1 = require("./utils");
const analyzers_1 = require("../analyzers");
function scan(options) {
    const start = Date.now();
    const info = (0, utils_1.detectServerInfo)(options.path);
    // Select analyzers
    let analyzers;
    if (options.analyzers && options.analyzers.length > 0) {
        analyzers = (0, analyzers_1.createAnalyzers)(options.analyzers);
    }
    else {
        analyzers = (0, analyzers_1.createAllAnalyzers)();
    }
    // Run all analyzers
    let findings = [];
    for (const analyzer of analyzers) {
        try {
            const results = analyzer.analyze(options.path, info);
            findings.push(...results);
        }
        catch (err) {
            if (options.verbose) {
                console.error(`  Warning: ${analyzer.name} analyzer failed: ${err}`);
            }
        }
    }
    // Deduplicate by id + file + line
    const seen = new Set();
    findings = findings.filter((f) => {
        const key = `${f.id}:${f.location?.file || ""}:${f.location?.line || 0}`;
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
    // Sort by severity (critical first)
    findings.sort((a, b) => models_1.SEVERITY_ORDER[b.severity] - models_1.SEVERITY_ORDER[a.severity]);
    // Build summary
    const summary = {
        total: findings.length,
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
        low: findings.filter((f) => f.severity === "low").length,
        info: findings.filter((f) => f.severity === "info").length,
        categories: {},
    };
    for (const f of findings) {
        summary.categories[f.category] = (summary.categories[f.category] || 0) + 1;
    }
    return {
        serverInfo: info,
        findings,
        scanDuration: Date.now() - start,
        timestamp: new Date().toISOString(),
        version: models_1.VERSION,
        summary,
    };
}
//# sourceMappingURL=scanner.js.map