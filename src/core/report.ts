import * as path from "path";
import { ScanResult, ReportFormat, Finding, Severity } from "./models";

// ─── Color helpers (ANSI) ─────────────────────────────────────────

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgYellow: "\x1b[43m",
  bgGreen: "\x1b[42m",
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: `${C.bgRed}${C.white}${C.bold}`,
  high: `${C.red}${C.bold}`,
  medium: `${C.yellow}`,
  low: `${C.blue}`,
  info: `${C.dim}`,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

// ─── Text Report ──────────────────────────────────────────────────

function textReport(result: ScanResult, noColor = false): string {
  const c = noColor
    ? Object.fromEntries(Object.keys(C).map((k) => [k, ""]))
    : C;
  const sc = noColor
    ? Object.fromEntries(Object.keys(SEVERITY_COLORS).map((k) => [k, ""]))
    : SEVERITY_COLORS;
  const r = c.reset || "";

  const lines: string[] = [];

  lines.push("");
  lines.push(`${c.bold}╔══════════════════════════════════════════════════════╗${r}`);
  lines.push(`${c.bold}║         MCP Security Auditor - Scan Report          ║${r}`);
  lines.push(`${c.bold}╚══════════════════════════════════════════════════════╝${r}`);
  lines.push("");

  // Server info
  lines.push(`${c.cyan}Server:${r}    ${result.serverInfo.name}${result.serverInfo.version ? ` v${result.serverInfo.version}` : ""}`);
  lines.push(`${c.cyan}Language:${r}  ${result.serverInfo.language}`);
  if (result.serverInfo.framework) lines.push(`${c.cyan}Framework:${r} ${result.serverInfo.framework}`);
  if (result.serverInfo.transportType) lines.push(`${c.cyan}Transport:${r} ${result.serverInfo.transportType}`);
  lines.push(`${c.cyan}Tools:${r}     ${result.serverInfo.tools.length} detected [${result.serverInfo.tools.map(t => t.name).join(", ") || "none"}]`);
  lines.push(`${c.cyan}Files:${r}     ${result.serverInfo.sourceFiles.length} source files scanned`);
  lines.push(`${c.cyan}Duration:${r}  ${result.scanDuration}ms`);
  lines.push("");

  // Summary bar
  const s = result.summary;
  lines.push(`${c.bold}Summary:${r} ${s.total} findings`);
  if (s.critical > 0) lines.push(`  ${SEVERITY_ICONS.critical} Critical: ${s.critical}`);
  if (s.high > 0)     lines.push(`  ${SEVERITY_ICONS.high} High:     ${s.high}`);
  if (s.medium > 0)   lines.push(`  ${SEVERITY_ICONS.medium} Medium:   ${s.medium}`);
  if (s.low > 0)      lines.push(`  ${SEVERITY_ICONS.low} Low:      ${s.low}`);
  if (s.info > 0)     lines.push(`  ${SEVERITY_ICONS.info} Info:     ${s.info}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(`${c.green}${c.bold}✓ No security issues found!${r}`);
    return lines.join("\n");
  }

  lines.push(`${c.bold}─── Findings ───────────────────────────────────────────${r}`);
  lines.push("");

  for (const f of result.findings) {
    const sev = `${sc[f.severity]} ${f.severity.toUpperCase()} ${r}`;
    lines.push(`${sev} ${c.bold}${f.title}${r}  [${f.id}]`);
    lines.push(`  ${f.description}`);
    if (f.location) {
      const relFile = f.location.file;
      lines.push(`  ${c.dim}at ${relFile}:${f.location.line}${r}`);
      if (f.location.snippet) {
        lines.push(`  ${c.dim}${f.location.snippet.split("\n").join(`\n  ${c.dim}`)}${r}`);
      }
    }
    if (f.cwe) lines.push(`  ${c.dim}CWE: ${f.cwe}${r}`);
    if (f.remediation) lines.push(`  ${c.green}Fix: ${f.remediation.description}${r}`);
    lines.push("");
  }

  return lines.join("\n");
}

// ─── JSON Report ──────────────────────────────────────────────────

function jsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

// ─── SARIF Report ─────────────────────────────────────────────────

function sarifReport(result: ScanResult): string {
  const severityMap: Record<Severity, string> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
    info: "note",
  };

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "mcp-security-auditor",
          version: result.version,
          informationUri: "https://github.com/mcp-security-auditor/mcp-security-auditor-npm",
          rules: result.findings.map((f) => ({
            id: f.id,
            shortDescription: { text: f.title },
            fullDescription: { text: f.description },
            defaultConfiguration: { level: severityMap[f.severity] },
            properties: {
              severity: f.severity,
              category: f.category,
              ...(f.cwe ? { cwe: f.cwe } : {}),
            },
          })),
        },
      },
      results: result.findings.map((f) => ({
        ruleId: f.id,
        level: severityMap[f.severity],
        message: { text: f.description },
        locations: f.location
          ? [{
              physicalLocation: {
                artifactLocation: { uri: f.location.file.replace(/\\/g, "/") },
                region: { startLine: f.location.line },
              },
            }]
          : [],
        properties: {
          confidence: f.confidence,
          category: f.category,
        },
      })),
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

// ─── HTML Report ──────────────────────────────────────────────────

function htmlReport(result: ScanResult): string {
  const s = result.summary;
  const sevColor: Record<Severity, string> = {
    critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#2563eb", info: "#6b7280",
  };

  const findingsHtml = result.findings
    .map((f) => {
      const loc = f.location
        ? `<span class="loc">${escHtml(f.location.file)}:${f.location.line}</span>`
        : "";
      const snippet = f.location?.snippet
        ? `<pre class="snippet">${escHtml(f.location.snippet)}</pre>`
        : "";
      return `
    <div class="finding sev-${f.severity}">
      <div class="finding-header">
        <span class="badge" style="background:${sevColor[f.severity]}">${f.severity.toUpperCase()}</span>
        <strong>${escHtml(f.title)}</strong>
        <code class="finding-id">${escHtml(f.id)}</code>
      </div>
      <p>${escHtml(f.description)}</p>
      ${loc}${snippet}
      ${f.cwe ? `<span class="cwe">${escHtml(f.cwe)}</span>` : ""}
    </div>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Security Audit - ${escHtml(result.serverInfo.name)}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
  .container { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #f8fafc; }
  .subtitle { color: #94a3b8; margin-bottom: 2rem; }
  .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .info-card { background: #1e293b; border-radius: 8px; padding: 1rem; }
  .info-card label { color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .info-card .value { font-size: 1.1rem; color: #f1f5f9; margin-top: 0.25rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .summary-item { background: #1e293b; border-radius: 8px; padding: 0.75rem 1.25rem; text-align: center; min-width: 80px; }
  .summary-item .count { font-size: 1.5rem; font-weight: 700; }
  .summary-item .label { font-size: 0.7rem; text-transform: uppercase; color: #94a3b8; }
  .finding { background: #1e293b; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 0.75rem; border-left: 4px solid; }
  .sev-critical { border-left-color: #dc2626; }
  .sev-high { border-left-color: #ea580c; }
  .sev-medium { border-left-color: #ca8a04; }
  .sev-low { border-left-color: #2563eb; }
  .sev-info { border-left-color: #6b7280; }
  .finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; flex-wrap: wrap; }
  .badge { color: #fff; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.05em; }
  .finding-id { color: #64748b; font-size: 0.75rem; }
  .finding p { color: #cbd5e1; font-size: 0.9rem; line-height: 1.5; }
  .loc { display: inline-block; color: #64748b; font-size: 0.8rem; margin-top: 0.5rem; }
  .snippet { background: #0f172a; padding: 0.75rem; border-radius: 4px; font-size: 0.75rem; overflow-x: auto; margin-top: 0.5rem; color: #94a3b8; line-height: 1.4; }
  .cwe { color: #64748b; font-size: 0.75rem; }
  .clean { text-align: center; padding: 3rem; color: #22c55e; font-size: 1.2rem; }
  .footer { text-align: center; color: #475569; margin-top: 2rem; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ MCP Security Audit Report</h1>
  <p class="subtitle">${escHtml(result.serverInfo.name)}${result.serverInfo.version ? ` v${result.serverInfo.version}` : ""} — ${result.timestamp}</p>
  
  <div class="info-grid">
    <div class="info-card"><label>Language</label><div class="value">${result.serverInfo.language}</div></div>
    <div class="info-card"><label>Framework</label><div class="value">${result.serverInfo.framework || "—"}</div></div>
    <div class="info-card"><label>Transport</label><div class="value">${result.serverInfo.transportType || "—"}</div></div>
    <div class="info-card"><label>Tools</label><div class="value">${result.serverInfo.tools.length} detected</div></div>
    <div class="info-card"><label>Files Scanned</label><div class="value">${result.serverInfo.sourceFiles.length}</div></div>
    <div class="info-card"><label>Duration</label><div class="value">${result.scanDuration}ms</div></div>
  </div>

  <div class="summary">
    <div class="summary-item"><div class="count" style="color:#dc2626">${s.critical}</div><div class="label">Critical</div></div>
    <div class="summary-item"><div class="count" style="color:#ea580c">${s.high}</div><div class="label">High</div></div>
    <div class="summary-item"><div class="count" style="color:#ca8a04">${s.medium}</div><div class="label">Medium</div></div>
    <div class="summary-item"><div class="count" style="color:#2563eb">${s.low}</div><div class="label">Low</div></div>
    <div class="summary-item"><div class="count" style="color:#6b7280">${s.info}</div><div class="label">Info</div></div>
    <div class="summary-item"><div class="count" style="color:#f8fafc">${s.total}</div><div class="label">Total</div></div>
  </div>

  ${result.findings.length === 0 ? '<div class="clean">✅ No security issues found!</div>' : findingsHtml}
  
  <div class="footer">Generated by mcp-security-auditor v${result.version}</div>
</div>
</body>
</html>`;
}

// ─── Markdown Report ──────────────────────────────────────────────

function markdownReport(result: ScanResult): string {
  const s = result.summary;
  const lines: string[] = [];

  lines.push(`# 🛡️ MCP Security Audit Report`);
  lines.push("");
  lines.push(`**Server:** ${result.serverInfo.name}${result.serverInfo.version ? ` v${result.serverInfo.version}` : ""}`);
  lines.push(`**Language:** ${result.serverInfo.language} | **Framework:** ${result.serverInfo.framework || "—"} | **Transport:** ${result.serverInfo.transportType || "—"}`);
  lines.push(`**Files scanned:** ${result.serverInfo.sourceFiles.length} | **Duration:** ${result.scanDuration}ms | **Date:** ${result.timestamp}`);
  lines.push("");
  lines.push(`## Summary`);
  lines.push("");
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| 🔴 Critical | ${s.critical} |`);
  lines.push(`| 🟠 High | ${s.high} |`);
  lines.push(`| 🟡 Medium | ${s.medium} |`);
  lines.push(`| 🔵 Low | ${s.low} |`);
  lines.push(`| ⚪ Info | ${s.info} |`);
  lines.push(`| **Total** | **${s.total}** |`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(`> ✅ **No security issues found!**`);
    return lines.join("\n");
  }

  lines.push(`## Findings`);
  lines.push("");

  for (const f of result.findings) {
    lines.push(`### ${SEVERITY_ICONS[f.severity]} [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push("");
    lines.push(`**ID:** \`${f.id}\` | **Confidence:** ${f.confidence}${f.cwe ? ` | **CWE:** ${f.cwe}` : ""}`);
    lines.push("");
    lines.push(f.description);
    if (f.location) {
      lines.push("");
      lines.push(`**Location:** \`${f.location.file}:${f.location.line}\``);
      if (f.location.snippet) {
        lines.push("```");
        lines.push(f.location.snippet);
        lines.push("```");
      }
    }
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  lines.push(`*Generated by mcp-security-auditor v${result.version}*`);
  return lines.join("\n");
}

// ─── Helper ───────────────────────────────────────────────────────

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── Export ───────────────────────────────────────────────────────

export function generateReport(result: ScanResult, format: ReportFormat, noColor = false): string {
  switch (format) {
    case "json": return jsonReport(result);
    case "sarif": return sarifReport(result);
    case "html": return htmlReport(result);
    case "markdown": return markdownReport(result);
    case "text":
    default: return textReport(result, noColor);
  }
}
