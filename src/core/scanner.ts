import {
  ScanResult, ScanSummary, ScanOptions, Finding, FindingCategory,
  SEVERITY_ORDER, VERSION,
} from "./models";
import { detectServerInfo } from "./utils";
import { createAllAnalyzers, createAnalyzers, BaseAnalyzer } from "../analyzers";

export function scan(options: ScanOptions): ScanResult {
  const start = Date.now();
  const info = detectServerInfo(options.path);

  // Select analyzers
  let analyzers: BaseAnalyzer[];
  if (options.analyzers && options.analyzers.length > 0) {
    analyzers = createAnalyzers(options.analyzers);
  } else {
    analyzers = createAllAnalyzers();
  }

  // Run all analyzers
  let findings: Finding[] = [];
  for (const analyzer of analyzers) {
    try {
      const results = analyzer.analyze(options.path, info);
      findings.push(...results);
    } catch (err) {
      if (options.verbose) {
        console.error(`  Warning: ${analyzer.name} analyzer failed: ${err}`);
      }
    }
  }

  // Deduplicate by id + file + line
  const seen = new Set<string>();
  findings = findings.filter((f) => {
    const key = `${f.id}:${f.location?.file || ""}:${f.location?.line || 0}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by severity (critical first)
  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  // Build summary
  const summary: ScanSummary = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
    categories: {} as Record<FindingCategory, number>,
  };

  for (const f of findings) {
    summary.categories[f.category] = (summary.categories[f.category] || 0) + 1;
  }

  return {
    serverInfo: info,
    findings,
    scanDuration: Date.now() - start,
    timestamp: new Date().toISOString(),
    version: VERSION,
    summary,
  };
}
