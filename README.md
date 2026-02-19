# 🛡️ MCP Security Auditor

Security scanner for **MCP (Model Context Protocol) servers**. Detect vulnerabilities, hardcoded secrets, injection risks, and misconfigurations before deployment.

Works with **TypeScript, JavaScript, and Python** MCP servers built with any framework (official MCP SDK, FastMCP, etc).

```bash
npx mcp-security-auditor scan ./my-mcp-server
```

## Why?

MCP servers give AI assistants (Claude, Copilot, Cursor) access to databases, APIs, filesystems, and more. A single misconfigured server can expose your entire infrastructure. This tool catches security issues **before** they reach production.

## Quick Start

**Zero install — scan any MCP server:**

```bash
npx mcp-security-auditor scan ./my-mcp-server
```

**Or install globally:**

```bash
npm install -g mcp-security-auditor
mcp-audit scan ./my-mcp-server
```

## What It Detects

| Analyzer | What It Finds |
|----------|--------------|
| **secrets** | API keys, passwords, tokens, private keys, AWS/GitHub/OpenAI/Anthropic credentials |
| **static** | `eval()`, `exec()`, command execution, unsafe deserialization, file system writes |
| **injection** | Prompt injection, SQL injection, template injection, NoSQL injection |
| **permissions** | Wildcard permissions, missing auth, root filesystem access, disabled security |
| **network** | Insecure HTTP, SSRF, TLS bypass, CORS wildcard, binding to all interfaces |
| **config** | Debug mode, stack trace exposure, missing .env templates, hardcoded ports |
| **dependencies** | Wildcard versions, typosquatting, missing lockfiles, suspicious packages |

## Output Formats

```bash
# Terminal (default, with colors)
mcp-audit scan ./server

# HTML report (shareable, dark theme)
mcp-audit scan ./server -f html -o report.html

# JSON (programmatic use)
mcp-audit scan ./server -f json -o results.json

# SARIF (GitHub Security, Azure DevOps)
mcp-audit scan ./server -f sarif -o results.sarif

# Markdown (docs, README badges)
mcp-audit scan ./server -f markdown -o report.md
```

## CI/CD Integration

### GitHub Actions

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx mcp-security-auditor ci . --fail-on high -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
mcp-security:
  script:
    - npx mcp-security-auditor ci . --fail-on high -f json -o mcp-audit.json
  artifacts:
    reports:
      security: mcp-audit.json
```

### Azure DevOps

```yaml
- script: npx mcp-security-auditor ci . --fail-on high -f sarif -o $(Build.ArtifactStagingDirectory)/mcp-audit.sarif
  displayName: 'MCP Security Scan'
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
npx mcp-security-auditor ci . --fail-on critical
```

## CLI Reference

```
mcp-audit scan <path>           Scan an MCP server directory
mcp-audit ci <path>             CI/CD mode (SARIF, exits non-zero on findings)
mcp-audit analyzers             List available analyzers
mcp-audit --version             Show version

Options:
  -f, --format <format>         text | json | sarif | html | markdown
  -o, --output <file>           Write report to file
  --fail-on <severity>          Exit 1 if findings >= severity (critical|high|medium|low)
  -a, --analyzers <list>        Run specific analyzers (comma-separated)
  -V, --verbose                 Detailed scan progress
  --no-color                    Disable colors
```

## Programmatic API

```typescript
import { scan, generateReport } from "mcp-security-auditor";

const result = scan({ path: "./my-mcp-server", format: "json" });

console.log(`Found ${result.summary.total} issues`);
console.log(`Critical: ${result.summary.critical}`);

// Generate HTML report
const html = generateReport(result, "html");
```

## Supported MCP Frameworks

- **@modelcontextprotocol/sdk** (Official TypeScript SDK)
- **FastMCP** (Python)
- **mcp-python-sdk** (Official Python SDK)
- Any custom MCP server implementation

## Example Output

```
╔══════════════════════════════════════════════════════╗
║         MCP Security Auditor - Scan Report          ║
╚══════════════════════════════════════════════════════╝

Server:    my-mcp-server v1.0.0
Language:  typescript
Framework: mcp-sdk
Transport: stdio
Tools:     3 detected [query_db, write_file, run_command]
Files:     12 source files scanned
Duration:  45ms

Summary: 8 findings
  🔴 Critical: 2
  🟠 High:     3
  🟡 Medium:   2
  🔵 Low:      1

─── Findings ───────────────────────────────────────────

 CRITICAL  Hardcoded API Key  [secrets-api-key]
  API key found hardcoded in source code. Use environment variables instead.
  at src/config.ts:15
  CWE: CWE-798

 HIGH  Use of eval()  [static-eval]
  eval() executes arbitrary code and is a major security risk.
  at src/handler.ts:42
  CWE: CWE-95
```

## Also Available on PyPI

```bash
pip install mcp-security-auditor
mcp-audit scan ./my-mcp-server
```

## Contributing

Issues and PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
