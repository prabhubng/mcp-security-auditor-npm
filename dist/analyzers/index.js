"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ANALYZERS = exports.DependenciesAnalyzer = exports.ConfigurationAnalyzer = exports.NetworkAnalyzer = exports.PermissionsAnalyzer = exports.InjectionAnalyzer = exports.StaticCodeAnalyzer = exports.SecretsAnalyzer = exports.BaseAnalyzer = void 0;
exports.createAllAnalyzers = createAllAnalyzers;
exports.createAnalyzers = createAnalyzers;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const utils_1 = require("../core/utils");
// ─── Base Analyzer ────────────────────────────────────────────────
class BaseAnalyzer {
    finding(id, title, description, severity, file, line, content, extra) {
        const f = {
            id: `${this.name}-${id}`,
            title, description, severity,
            category: this.category,
            confidence: "high",
            ...extra,
        };
        if (file) {
            f.location = {
                file: file,
                line: line || 0,
                snippet: content && line ? (0, utils_1.getSnippet)(content, line) : undefined,
            };
        }
        return f;
    }
    scanFilesByPattern(files, patterns) {
        const findings = [];
        for (const file of files) {
            const content = (0, utils_1.readFileSafe)(file);
            if (!content)
                continue;
            const lines = content.split("\n");
            for (const { pattern, id, title, desc, severity, cwe } of patterns) {
                for (let i = 0; i < lines.length; i++) {
                    if (pattern.test(lines[i])) {
                        findings.push(this.finding(id, title, desc, severity, file, i + 1, content, { cwe }));
                    }
                }
            }
        }
        return findings;
    }
}
exports.BaseAnalyzer = BaseAnalyzer;
// ─── 1. Secrets Analyzer ──────────────────────────────────────────
class SecretsAnalyzer extends BaseAnalyzer {
    name = "secrets";
    category = "secrets";
    patterns = [
        { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/i,
            id: "api-key", title: "Hardcoded API Key", desc: "API key found hardcoded in source code. Use environment variables instead.", severity: "critical", cwe: "CWE-798" },
        { pattern: /(?:secret|password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/i,
            id: "password", title: "Hardcoded Password/Secret", desc: "Password or secret found in source code.", severity: "critical", cwe: "CWE-798" },
        { pattern: /(?:aws_access_key_id|aws_secret)\s*[:=]\s*["'][A-Za-z0-9/+=]{16,}["']/i,
            id: "aws-key", title: "AWS Credentials", desc: "AWS access key or secret found in source code.", severity: "critical", cwe: "CWE-798" },
        { pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/,
            id: "aws-access-key", title: "AWS Access Key ID", desc: "AWS Access Key ID pattern detected.", severity: "critical", cwe: "CWE-798" },
        { pattern: /ghp_[A-Za-z0-9_]{36}/,
            id: "github-token", title: "GitHub Personal Access Token", desc: "GitHub PAT found in source code.", severity: "critical", cwe: "CWE-798" },
        { pattern: /sk-[A-Za-z0-9]{32,}/,
            id: "openai-key", title: "OpenAI API Key", desc: "OpenAI API key pattern detected.", severity: "critical", cwe: "CWE-798" },
        { pattern: /sk-ant-[A-Za-z0-9_\-]{80,}/,
            id: "anthropic-key", title: "Anthropic API Key", desc: "Anthropic API key pattern detected.", severity: "critical", cwe: "CWE-798" },
        { pattern: /xox[bpas]-[A-Za-z0-9\-]{10,}/,
            id: "slack-token", title: "Slack Token", desc: "Slack bot/user token found in source code.", severity: "high", cwe: "CWE-798" },
        { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
            id: "private-key", title: "Private Key", desc: "Private key found embedded in source code.", severity: "critical", cwe: "CWE-321" },
        { pattern: /(?:mongodb(?:\+srv)?:\/\/)[^\s"']+:[^\s"']+@/i,
            id: "db-connection", title: "Database Connection String with Credentials", desc: "Database URI with embedded credentials.", severity: "high", cwe: "CWE-798" },
        { pattern: /(?:postgres|mysql|mssql):\/\/[^\s"']+:[^\s"']+@/i,
            id: "db-uri", title: "Database URI with Password", desc: "SQL database connection string with embedded password.", severity: "high", cwe: "CWE-798" },
        { pattern: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/,
            id: "bearer-token", title: "Bearer Token", desc: "Hardcoded bearer token in source.", severity: "high", cwe: "CWE-798" },
    ];
    analyze(scanPath, info) {
        const files = info.sourceFiles.filter(f => {
            const base = path.basename(f).toLowerCase();
            return !base.includes("test") && !base.includes("spec") && !base.includes("mock")
                && !base.endsWith(".d.ts") && !base.includes("example");
        });
        return this.scanFilesByPattern(files, this.patterns);
    }
}
exports.SecretsAnalyzer = SecretsAnalyzer;
// ─── 2. Static Code Analyzer ──────────────────────────────────────
class StaticCodeAnalyzer extends BaseAnalyzer {
    name = "static";
    category = "static-code";
    patterns = [
        // JavaScript/TypeScript dangerous patterns
        { pattern: /\beval\s*\(/,
            id: "eval", title: "Use of eval()", desc: "eval() executes arbitrary code and is a major security risk. Use safer alternatives.", severity: "critical", cwe: "CWE-95" },
        { pattern: /new\s+Function\s*\(/,
            id: "new-function", title: "Dynamic Function Constructor", desc: "new Function() is equivalent to eval() and executes arbitrary code.", severity: "critical", cwe: "CWE-95" },
        { pattern: /child_process|exec\s*\(|execSync\s*\(|spawn\s*\(/,
            id: "command-exec", title: "Command Execution", desc: "Executing system commands. Ensure inputs are sanitized to prevent command injection.", severity: "high", cwe: "CWE-78" },
        { pattern: /subprocess\.(run|call|Popen|check_output)\s*\(/,
            id: "py-subprocess", title: "Python Subprocess Execution", desc: "Subprocess execution detected. Validate all inputs to prevent command injection.", severity: "high", cwe: "CWE-78" },
        { pattern: /\bos\.system\s*\(|\bos\.popen\s*\(/,
            id: "py-os-exec", title: "Python OS Command Execution", desc: "os.system/popen runs shell commands. Use subprocess with proper input validation.", severity: "critical", cwe: "CWE-78" },
        { pattern: /\b(?:exec|execfile)\s*\(/,
            id: "py-exec", title: "Python exec()", desc: "exec() executes arbitrary Python code. This is a critical security risk.", severity: "critical", cwe: "CWE-95" },
        // File system dangers
        { pattern: /fs\.(?:writeFile|appendFile|mkdir|rmdir|unlink|rm)(?:Sync)?\s*\(/,
            id: "fs-write", title: "File System Write Operation", desc: "MCP server performs file system writes. Ensure path traversal protection and proper access controls.", severity: "medium", cwe: "CWE-73" },
        { pattern: /\.\.\/|\.\.\\|\.\.[/\\]/,
            id: "path-traversal", title: "Potential Path Traversal", desc: "Relative path with parent directory reference. Validate and sanitize all file paths.", severity: "medium", cwe: "CWE-22" },
        // Unsafe deserialization
        { pattern: /JSON\.parse\s*\(\s*(?:req|request|body|input|user|data)/,
            id: "unsafe-json-parse", title: "Unsanitized JSON Parse", desc: "JSON.parse on user-controlled input without validation.", severity: "medium", cwe: "CWE-502" },
        { pattern: /pickle\.loads?\s*\(|yaml\.(?:load|unsafe_load)\s*\(/,
            id: "unsafe-deser", title: "Unsafe Deserialization", desc: "Unsafe deserialization can lead to remote code execution. Use safe loaders.", severity: "critical", cwe: "CWE-502" },
        // Shell=True
        { pattern: /shell\s*=\s*True/,
            id: "shell-true", title: "Shell=True in Subprocess", desc: "Using shell=True enables shell injection attacks. Pass arguments as a list instead.", severity: "high", cwe: "CWE-78" },
    ];
    analyze(scanPath, info) {
        return this.scanFilesByPattern(info.sourceFiles, this.patterns);
    }
}
exports.StaticCodeAnalyzer = StaticCodeAnalyzer;
// ─── 3. Injection Analyzer ────────────────────────────────────────
class InjectionAnalyzer extends BaseAnalyzer {
    name = "injection";
    category = "injection";
    patterns = [
        // Prompt injection risks
        { pattern: /prompt\s*[+=]\s*.*(?:input|user|request|body|query|param)/i,
            id: "prompt-concat", title: "User Input in Prompt Construction", desc: "User-controlled input concatenated into prompts. Apply input sanitization and prompt guards.", severity: "high", cwe: "CWE-74" },
        { pattern: /f["'].*\{.*(?:user_input|request|query|body).*\}.*["']/,
            id: "fstring-inject", title: "F-String Prompt Injection", desc: "User input interpolated via f-string into prompt text.", severity: "high", cwe: "CWE-74" },
        { pattern: /`[^`]*\$\{.*(?:input|user|request|body|query|param).*\}[^`]*`/,
            id: "template-inject", title: "Template Literal Injection", desc: "User input in template literal string. Sanitize before use in prompts.", severity: "high", cwe: "CWE-74" },
        // SQL injection  
        { pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*(?:\+|`|\$\{|\.format|%s)/i,
            id: "sql-inject", title: "Potential SQL Injection", desc: "SQL query built with string concatenation. Use parameterized queries.", severity: "critical", cwe: "CWE-89" },
        { pattern: /\.(?:query|execute|exec)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*\+|f["'])/,
            id: "sql-dynamic", title: "Dynamic SQL Query", desc: "Database query with dynamic string construction. Use prepared statements.", severity: "high", cwe: "CWE-89" },
        // Command injection
        { pattern: /exec\s*\(\s*(?:`[^`]*\$\{|["'][^"']*\+|f["'].*\{)/,
            id: "cmd-inject", title: "Command Injection Risk", desc: "Command execution with user-controlled input interpolation.", severity: "critical", cwe: "CWE-78" },
        // NoSQL injection
        { pattern: /\$(?:where|gt|gte|lt|lte|ne|in|nin|regex)\s*:/,
            id: "nosql-inject", title: "NoSQL Operator in Query", desc: "MongoDB operators in query may allow NoSQL injection if user input is not validated.", severity: "medium", cwe: "CWE-943" },
    ];
    analyze(scanPath, info) {
        return this.scanFilesByPattern(info.sourceFiles, this.patterns);
    }
}
exports.InjectionAnalyzer = InjectionAnalyzer;
// ─── 4. Permissions Analyzer ──────────────────────────────────────
class PermissionsAnalyzer extends BaseAnalyzer {
    name = "permissions";
    category = "permissions";
    analyze(scanPath, info) {
        const findings = [];
        // Check tool annotations
        for (const tool of info.tools) {
            if (!tool.annotations || !tool.annotations.readOnlyHint) {
                // Tools without explicit read-only marking
            }
        }
        // Check for overly broad permissions in source
        for (const file of info.sourceFiles) {
            const content = (0, utils_1.readFileSafe)(file);
            if (!content)
                continue;
            const lines = content.split("\n");
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const lineNum = i + 1;
                // Wildcard permissions
                if (/["']\*["']|permissions?\s*[:=]\s*["']all["']/i.test(line)) {
                    findings.push(this.finding("wildcard-perm", "Wildcard Permissions", "Wildcard (*) or 'all' permission grants unrestricted access. Apply least-privilege principle.", "high", file, lineNum, content, { cwe: "CWE-250" }));
                }
                // Unrestricted file access
                if (/(?:readdir|readFile|glob)\s*\(\s*["']\/["']|rootPath\s*[:=]\s*["']\/["']/i.test(line)) {
                    findings.push(this.finding("root-access", "Root Filesystem Access", "MCP server configured with root (/) filesystem access. Restrict to specific directories.", "critical", file, lineNum, content, { cwe: "CWE-250" }));
                }
                // No auth check
                if (/(?:app|server|router)\.(?:get|post|put|delete|all)\s*\(/.test(line) &&
                    !/auth|token|session|verify|middleware|guard/i.test(lines.slice(Math.max(0, i - 3), i + 3).join(" "))) {
                    // Only flag if it's an HTTP handler without nearby auth references
                    if (/(?:req|request)\s*(?:,|\))/.test(line)) {
                        findings.push(this.finding("no-auth", "HTTP Handler Without Authentication", "HTTP endpoint defined without visible authentication check nearby.", "medium", file, lineNum, content, { cwe: "CWE-306", confidence: "low" }));
                    }
                }
                // Disabled security  
                if (/(?:verify|auth|secure|csrf|cors)\s*[:=]\s*false/i.test(line)) {
                    findings.push(this.finding("disabled-security", "Security Feature Disabled", "A security feature is explicitly disabled. Review whether this is intentional.", "high", file, lineNum, content, { cwe: "CWE-693" }));
                }
            }
        }
        return findings;
    }
}
exports.PermissionsAnalyzer = PermissionsAnalyzer;
// ─── 5. Network Analyzer ──────────────────────────────────────────
class NetworkAnalyzer extends BaseAnalyzer {
    name = "network";
    category = "network";
    patterns = [
        // HTTP (not HTTPS)
        { pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/,
            id: "insecure-http", title: "Insecure HTTP URL", desc: "Non-localhost HTTP URL found. Use HTTPS for all external connections.", severity: "medium", cwe: "CWE-319" },
        // SSRF patterns
        { pattern: /(?:fetch|axios|request|got|http\.get)\s*\(\s*(?:user|input|req|body|query|param)/i,
            id: "ssrf", title: "Potential SSRF", desc: "HTTP request with user-controlled URL. Validate and allowlist target domains.", severity: "high", cwe: "CWE-918" },
        // Binding to all interfaces
        { pattern: /(?:listen|bind)\s*\(\s*(?:0\.0\.0\.0|["']0\.0\.0\.0["']|["']::["'])/,
            id: "bind-all", title: "Binding to All Network Interfaces", desc: "Server binds to 0.0.0.0, exposing it to all network interfaces. Bind to localhost for local-only MCP servers.", severity: "medium", cwe: "CWE-668" },
        // No TLS verification
        { pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']0["']|verify\s*=\s*False/,
            id: "tls-disabled", title: "TLS Verification Disabled", desc: "SSL/TLS certificate verification is disabled. This allows man-in-the-middle attacks.", severity: "high", cwe: "CWE-295" },
        // CORS wildcard
        { pattern: /(?:cors|Access-Control-Allow-Origin)\s*[:=]\s*["']\*["']/,
            id: "cors-wildcard", title: "CORS Wildcard Origin", desc: "CORS allows all origins (*). Restrict to specific trusted domains.", severity: "medium", cwe: "CWE-942" },
        // External data fetch without validation
        { pattern: /(?:fetch|axios|request)\s*\([^)]*\)\s*\.then\s*\([^)]*=>\s*[^)]*\.(?:json|text)\(\)/,
            id: "unvalidated-fetch", title: "Unvalidated External Data", desc: "External data fetched and parsed without validation. Validate response data before use.", severity: "low", cwe: "CWE-20" },
    ];
    analyze(scanPath, info) {
        return this.scanFilesByPattern(info.sourceFiles, this.patterns);
    }
}
exports.NetworkAnalyzer = NetworkAnalyzer;
// ─── 6. Configuration Analyzer ────────────────────────────────────
class ConfigurationAnalyzer extends BaseAnalyzer {
    name = "config";
    category = "configuration";
    analyze(scanPath, info) {
        const findings = [];
        for (const file of [...info.configFiles, ...info.sourceFiles]) {
            const content = (0, utils_1.readFileSafe)(file);
            if (!content)
                continue;
            const lines = content.split("\n");
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const lineNum = i + 1;
                // Debug mode enabled
                if (/(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1|["']true["'])/i.test(line) &&
                    !line.trim().startsWith("//") && !line.trim().startsWith("#")) {
                    findings.push(this.finding("debug-enabled", "Debug Mode Enabled", "Debug mode is enabled. Disable in production to prevent information disclosure.", "medium", file, lineNum, content, { cwe: "CWE-489" }));
                }
                // Verbose error messages
                if (/(?:stack|stackTrace|traceback)\s*[:=]|\.stack\b/i.test(line) &&
                    /(?:res|response|send|json|return)/i.test(line)) {
                    findings.push(this.finding("stack-exposure", "Stack Trace Exposure", "Stack trace may be sent in response. Sanitize error messages in production.", "medium", file, lineNum, content, { cwe: "CWE-209" }));
                }
                // Hardcoded localhost ports that might conflict
                if (/(?:PORT|port)\s*[:=]\s*(?:80|443|8080|3000|5000)\b/.test(line) &&
                    !line.trim().startsWith("//") && !line.trim().startsWith("#")) {
                    findings.push(this.finding("hardcoded-port", "Hardcoded Port Number", "Port is hardcoded instead of configurable. Use environment variables for deployment flexibility.", "low", file, lineNum, content));
                }
            }
        }
        // Check for missing .env.example
        if (!fs.existsSync(path.join(scanPath, ".env.example")) &&
            !fs.existsSync(path.join(scanPath, ".env.template"))) {
            const hasEnvRefs = info.sourceFiles.some(f => {
                const c = (0, utils_1.readFileSafe)(f);
                return c ? /process\.env\.|os\.environ|os\.getenv/i.test(c) : false;
            });
            if (hasEnvRefs) {
                findings.push(this.finding("no-env-template", "Missing .env Template", "Code references environment variables but no .env.example/.env.template exists. Include a template for safe configuration.", "low", undefined, undefined, undefined));
            }
        }
        // Check for .env in repo (should be gitignored)
        if (fs.existsSync(path.join(scanPath, ".env"))) {
            const gitignorePath = path.join(scanPath, ".gitignore");
            const gitignore = (0, utils_1.readFileSafe)(gitignorePath);
            if (!gitignore || !gitignore.includes(".env")) {
                findings.push(this.finding("env-not-ignored", ".env File May Not Be Gitignored", ".env file exists but may not be in .gitignore. Secrets could be committed to version control.", "high", path.join(scanPath, ".env"), 1, undefined, { cwe: "CWE-538" }));
            }
        }
        return findings;
    }
}
exports.ConfigurationAnalyzer = ConfigurationAnalyzer;
// ─── 7. Dependencies Analyzer ─────────────────────────────────────
class DependenciesAnalyzer extends BaseAnalyzer {
    name = "dependencies";
    category = "dependencies";
    // Known vulnerable or suspicious package prefixes
    suspiciousPackages = new Set([
        "event-stream", // historical supply chain attack
    ]);
    // Typosquatting detection: common package names and common typos
    popularPackages = {
        "express": ["expres", "expresss", "exress", "expess"],
        "lodash": ["lodahs", "lodasg", "lodas"],
        "axios": ["axois", "axos", "axio"],
        "react": ["raect", "recat", "reat"],
        "mongoose": ["mongose", "mongosse", "mongoos"],
    };
    analyze(scanPath, info) {
        const findings = [];
        // Check package.json dependencies
        const pkgPath = path.join(scanPath, "package.json");
        if (fs.existsSync(pkgPath)) {
            try {
                const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
                const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
                for (const [name, version] of Object.entries(allDeps)) {
                    const ver = String(version);
                    // Wildcard versions
                    if (ver === "*" || ver === "latest") {
                        findings.push(this.finding("wildcard-version", `Wildcard Version: ${name}`, `Package "${name}" uses "${ver}" version. Pin to a specific version for reproducible builds.`, "medium", pkgPath, 0, undefined, { cwe: "CWE-1104" }));
                    }
                    // Very old major versions (heuristic)
                    if (ver.startsWith("^0.") || ver.startsWith("~0.")) {
                        findings.push(this.finding("pre-stable", `Pre-1.0 Package: ${name}`, `Package "${name}" at ${ver} is pre-1.0 (unstable API). Evaluate for production readiness.`, "low", pkgPath, 0, undefined));
                    }
                    // Suspicious packages
                    if (this.suspiciousPackages.has(name)) {
                        findings.push(this.finding("suspicious-pkg", `Suspicious Package: ${name}`, `Package "${name}" has a known history of supply chain attacks. Review and consider alternatives.`, "high", pkgPath, 0, undefined, { cwe: "CWE-1104" }));
                    }
                    // Typosquatting check
                    for (const [real, typos] of Object.entries(this.popularPackages)) {
                        if (typos.includes(name)) {
                            findings.push(this.finding("typosquat", `Possible Typosquatting: ${name}`, `Package "${name}" looks like a typo of "${real}". Verify this is the intended package.`, "critical", pkgPath, 0, undefined, { cwe: "CWE-1104" }));
                        }
                    }
                }
                // Check for no lockfile
                if (!fs.existsSync(path.join(scanPath, "package-lock.json")) &&
                    !fs.existsSync(path.join(scanPath, "yarn.lock")) &&
                    !fs.existsSync(path.join(scanPath, "pnpm-lock.yaml"))) {
                    findings.push(this.finding("no-lockfile", "No Package Lock File", "No lock file found. Lock files ensure reproducible builds and prevent supply chain attacks.", "medium", pkgPath, 0, undefined, { cwe: "CWE-1104" }));
                }
            }
            catch { /* invalid package.json */ }
        }
        // Check Python requirements
        const reqPath = path.join(scanPath, "requirements.txt");
        if (fs.existsSync(reqPath)) {
            const content = (0, utils_1.readFileSafe)(reqPath);
            if (content) {
                const lines = content.split("\n");
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i].trim();
                    if (!line || line.startsWith("#"))
                        continue;
                    // Unpinned Python dependencies
                    if (!line.includes("==") && !line.includes(">=") && !line.includes("~=")) {
                        findings.push(this.finding("unpinned-py", `Unpinned Python Package: ${line}`, `Python package "${line}" has no version pin. Pin versions for reproducible builds.`, "medium", reqPath, i + 1, content));
                    }
                }
            }
        }
        return findings;
    }
}
exports.DependenciesAnalyzer = DependenciesAnalyzer;
// ─── Analyzer Registry ────────────────────────────────────────────
exports.ANALYZERS = {
    secrets: SecretsAnalyzer,
    static: StaticCodeAnalyzer,
    injection: InjectionAnalyzer,
    permissions: PermissionsAnalyzer,
    network: NetworkAnalyzer,
    config: ConfigurationAnalyzer,
    dependencies: DependenciesAnalyzer,
};
function createAllAnalyzers() {
    return Object.values(exports.ANALYZERS).map((Cls) => new Cls());
}
function createAnalyzers(names) {
    return names
        .filter((n) => n in exports.ANALYZERS)
        .map((n) => new exports.ANALYZERS[n]());
}
//# sourceMappingURL=index.js.map