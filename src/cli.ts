#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { scan } from "./core/scanner";
import { generateReport } from "./core/report";
import { ReportFormat, Severity, SEVERITY_ORDER, VERSION } from "./core/models";
import { ANALYZERS } from "./analyzers";

// ─── Argument Parsing ─────────────────────────────────────────────

interface CliArgs {
  command: "scan" | "help" | "version" | "analyzers";
  path?: string;
  format: ReportFormat;
  output?: string;
  failOn?: Severity;
  analyzers?: string[];
  verbose: boolean;
  noColor: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args = argv.slice(2);
  const result: CliArgs = {
    command: "help",
    format: "text",
    verbose: false,
    noColor: false,
  };

  if (args.length === 0) { result.command = "help"; return result; }

  const command = args[0];
  if (command === "--version" || command === "-v") { result.command = "version"; return result; }
  if (command === "--help" || command === "-h" || command === "help") { result.command = "help"; return result; }
  if (command === "analyzers" || command === "list-analyzers") { result.command = "analyzers"; return result; }

  if (command === "scan" || command === "ci") {
    result.command = "scan";
    // Find the path (first non-flag argument after command)
    let i = 1;
    while (i < args.length) {
      const arg = args[i];
      if (arg === "--format" || arg === "-f") { result.format = args[++i] as ReportFormat; }
      else if (arg === "--output" || arg === "-o") { result.output = args[++i]; }
      else if (arg === "--fail-on") { result.failOn = args[++i] as Severity; }
      else if (arg === "--analyzers" || arg === "-a") { result.analyzers = args[++i].split(","); }
      else if (arg === "--verbose" || arg === "-V") { result.verbose = true; }
      else if (arg === "--no-color") { result.noColor = true; }
      else if (!arg.startsWith("-")) { result.path = arg; }
      i++;
    }

    // Default path to current directory
    if (!result.path) result.path = ".";

    // CI command defaults
    if (command === "ci") {
      if (!result.failOn) result.failOn = "high";
      if (result.format === "text") result.format = "sarif";
    }
  } else {
    // Treat bare argument as scan path
    result.command = "scan";
    result.path = command;
    // Parse remaining args
    let i = 1;
    while (i < args.length) {
      const arg = args[i];
      if (arg === "--format" || arg === "-f") { result.format = args[++i] as ReportFormat; }
      else if (arg === "--output" || arg === "-o") { result.output = args[++i]; }
      else if (arg === "--fail-on") { result.failOn = args[++i] as Severity; }
      else if (arg === "--analyzers" || arg === "-a") { result.analyzers = args[++i].split(","); }
      else if (arg === "--verbose" || arg === "-V") { result.verbose = true; }
      else if (arg === "--no-color") { result.noColor = true; }
      i++;
    }
  }

  return result;
}

// ─── Commands ─────────────────────────────────────────────────────

function showHelp() {
  console.log(`
\x1b[1mmcp-security-auditor\x1b[0m v${VERSION}
Security scanner for MCP (Model Context Protocol) servers

\x1b[1mUSAGE:\x1b[0m
  mcp-audit scan <path>           Scan an MCP server directory
  mcp-audit ci <path>             CI/CD mode (SARIF output, exits non-zero on findings)
  mcp-audit analyzers             List available analyzers
  mcp-audit --version             Show version
  mcp-audit --help                Show this help

\x1b[1mSCAN OPTIONS:\x1b[0m
  -f, --format <format>           Output format: text, json, sarif, html, markdown
  -o, --output <file>             Write report to file (default: stdout for text/json)
  --fail-on <severity>            Exit with code 1 if findings >= severity (critical|high|medium|low)
  -a, --analyzers <list>          Comma-separated analyzer names to run
  -V, --verbose                   Show detailed scan progress
  --no-color                      Disable colored output

\x1b[1mEXAMPLES:\x1b[0m
  npx mcp-security-auditor scan ./my-mcp-server
  npx mcp-security-auditor scan ./server -f html -o report.html
  npx mcp-security-auditor ci ./server --fail-on high
  npx mcp-security-auditor scan . -f sarif -o results.sarif
  npx mcp-security-auditor scan ./server -a secrets,injection,static

\x1b[1mGITHUB ACTIONS:\x1b[0m
  - uses: actions/checkout@v4
  - run: npx mcp-security-auditor ci . --fail-on high -o results.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: results.sarif
`);
}

function showVersion() {
  console.log(`mcp-security-auditor v${VERSION}`);
}

function showAnalyzers() {
  console.log(`\n\x1b[1mAvailable Analyzers:\x1b[0m\n`);
  const descriptions: Record<string, string> = {
    secrets: "Detects hardcoded API keys, passwords, tokens, private keys, and connection strings",
    static: "Finds dangerous code patterns: eval(), exec(), command injection, unsafe deserialization",
    injection: "Identifies prompt injection, SQL injection, template injection, and command injection risks",
    permissions: "Checks for overly broad permissions, missing auth, wildcard access, disabled security",
    network: "Scans for insecure HTTP, SSRF vulnerabilities, TLS bypass, CORS misconfigs, bind-all",
    config: "Finds debug mode enabled, stack trace exposure, missing .env templates, hardcoded ports",
    dependencies: "Checks for wildcard versions, typosquatting, missing lockfiles, suspicious packages",
  };
  for (const name of Object.keys(ANALYZERS)) {
    console.log(`  \x1b[36m${name.padEnd(16)}\x1b[0m ${descriptions[name] || ""}`);
  }
  console.log("");
}

function runScan(args: CliArgs) {
  const scanPath = path.resolve(args.path!);

  if (!fs.existsSync(scanPath)) {
    console.error(`\x1b[31mError: Path not found: ${scanPath}\x1b[0m`);
    process.exit(2);
  }

  if (args.verbose) {
    console.log(`\x1b[2mScanning: ${scanPath}\x1b[0m`);
  }

  const result = scan({
    path: scanPath,
    format: args.format,
    output: args.output,
    failOn: args.failOn,
    analyzers: args.analyzers,
    verbose: args.verbose,
    noColor: args.noColor,
  });

  const report = generateReport(result, args.format, args.noColor);

  // Output
  if (args.output) {
    const outPath = path.resolve(args.output);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, report, "utf-8");
    console.log(`\x1b[32m✓ Report written to ${outPath}\x1b[0m`);
    console.log(`  ${result.summary.total} findings (${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low)`);
  } else {
    console.log(report);
  }

  // Exit code based on --fail-on
  if (args.failOn) {
    const threshold = SEVERITY_ORDER[args.failOn];
    const hasViolation = result.findings.some(
      (f) => SEVERITY_ORDER[f.severity] >= threshold
    );
    if (hasViolation) {
      if (args.output) {
        console.error(`\x1b[31m✗ Findings at or above "${args.failOn}" severity detected. Failing.\x1b[0m`);
      }
      process.exit(1);
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────

function main() {
  const args = parseArgs(process.argv);

  switch (args.command) {
    case "version": showVersion(); break;
    case "help": showHelp(); break;
    case "analyzers": showAnalyzers(); break;
    case "scan": runScan(args); break;
  }
}

main();
