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
exports.walkFiles = walkFiles;
exports.readFileSafe = readFileSafe;
exports.getSnippet = getSnippet;
exports.detectServerInfo = detectServerInfo;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const IGNORE_DIRS = new Set([
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "coverage", ".tox",
    "env", ".env", ".mypy_cache", ".pytest_cache", "egg-info",
]);
const SOURCE_EXTENSIONS = {
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".py": "python",
};
function walkFiles(dir, extensions) {
    const results = [];
    if (!fs.existsSync(dir))
        return results;
    function walk(currentDir) {
        let entries;
        try {
            entries = fs.readdirSync(currentDir, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const entry of entries) {
            if (entry.name.startsWith(".") && entry.isDirectory())
                continue;
            if (IGNORE_DIRS.has(entry.name) && entry.isDirectory())
                continue;
            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory()) {
                walk(fullPath);
            }
            else if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                if (!extensions || extensions.includes(ext)) {
                    results.push(fullPath);
                }
            }
        }
    }
    walk(dir);
    return results;
}
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, "utf-8");
    }
    catch {
        return null;
    }
}
function getSnippet(content, lineNum, context = 2) {
    const lines = content.split("\n");
    const start = Math.max(0, lineNum - 1 - context);
    const end = Math.min(lines.length, lineNum + context);
    return lines.slice(start, end)
        .map((l, i) => {
        const num = start + i + 1;
        const marker = num === lineNum ? ">>>" : "   ";
        return `${marker} ${String(num).padStart(4)} | ${l}`;
    }).join("\n");
}
function detectServerInfo(scanPath) {
    const info = {
        name: path.basename(scanPath),
        tools: [],
        language: "unknown",
        configFiles: [],
        sourceFiles: [],
    };
    // Detect language and config files
    const allFiles = walkFiles(scanPath);
    const configNames = [
        "package.json", "tsconfig.json", "pyproject.toml", "setup.py",
        "setup.cfg", "requirements.txt", ".mcp.json", "mcp.json",
        "claude_desktop_config.json",
    ];
    for (const f of allFiles) {
        const basename = path.basename(f);
        const ext = path.extname(f).toLowerCase();
        if (configNames.includes(basename)) {
            info.configFiles.push(f);
        }
        if (ext in SOURCE_EXTENSIONS) {
            info.sourceFiles.push(f);
        }
    }
    // Detect primary language
    const langCount = {};
    for (const f of info.sourceFiles) {
        const ext = path.extname(f).toLowerCase();
        const lang = SOURCE_EXTENSIONS[ext];
        if (lang)
            langCount[lang] = (langCount[lang] || 0) + 1;
    }
    const topLang = Object.entries(langCount).sort((a, b) => b[1] - a[1])[0];
    if (topLang)
        info.language = topLang[0];
    // Detect framework and transport from package.json
    const pkgJsonPath = path.join(scanPath, "package.json");
    if (fs.existsSync(pkgJsonPath)) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
            info.name = pkg.name || info.name;
            info.version = pkg.version;
            info.description = pkg.description;
            const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
            if (allDeps["@modelcontextprotocol/sdk"])
                info.framework = "mcp-sdk";
            if (allDeps["fastmcp"])
                info.framework = "fastmcp";
            if (pkg.main)
                info.entryPoint = pkg.main;
        }
        catch { /* skip */ }
    }
    // Detect framework from pyproject.toml
    const pyprojectPath = path.join(scanPath, "pyproject.toml");
    if (fs.existsSync(pyprojectPath)) {
        const content = readFileSafe(pyprojectPath);
        if (content) {
            if (content.includes("mcp"))
                info.framework = "mcp-python-sdk";
            if (content.includes("fastmcp"))
                info.framework = "fastmcp";
            const nameMatch = content.match(/name\s*=\s*"([^"]+)"/);
            if (nameMatch)
                info.name = nameMatch[1];
            const verMatch = content.match(/version\s*=\s*"([^"]+)"/);
            if (verMatch)
                info.version = verMatch[1];
        }
    }
    // Detect tools from source code
    info.tools = detectTools(info.sourceFiles);
    // Detect transport
    for (const f of info.sourceFiles) {
        const content = readFileSafe(f);
        if (!content)
            continue;
        if (/StdioServerTransport|stdio_server|transport.*stdio/i.test(content)) {
            info.transportType = "stdio";
        }
        else if (/SSEServerTransport|sse_server|transport.*sse/i.test(content)) {
            info.transportType = "sse";
        }
        else if (/StreamableHTTPServerTransport|http_server/i.test(content)) {
            info.transportType = "http";
        }
        if (info.transportType)
            break;
    }
    return info;
}
function detectTools(sourceFiles) {
    const tools = [];
    const seen = new Set();
    for (const f of sourceFiles) {
        const content = readFileSafe(f);
        if (!content)
            continue;
        // TypeScript/JavaScript patterns
        // server.tool("name", ...) or .addTool({ name: "..." })
        const tsPatterns = [
            /\.tool\s*\(\s*["']([^"']+)["']/g,
            /\.addTool\s*\(\s*\{[^}]*name:\s*["']([^"']+)["']/g,
            /name:\s*["']([^"']+)["'][^}]*(?:description|inputSchema)/g,
        ];
        // Python patterns  
        // @server.tool() / def tool_name / server.add_tool
        const pyPatterns = [
            /@(?:server|mcp|app)\.tool\s*\(\s*(?:name\s*=\s*)?["']([^"']+)["']/g,
            /add_tool\s*\(\s*["']([^"']+)["']/g,
            /@(?:server|mcp|app)\.tool\s*\(\s*\)\s*\n\s*(?:async\s+)?def\s+(\w+)/g,
        ];
        const patterns = [...tsPatterns, ...pyPatterns];
        for (const pattern of patterns) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const toolName = match[1];
                if (!seen.has(toolName)) {
                    seen.add(toolName);
                    tools.push({ name: toolName });
                }
            }
        }
    }
    return tools;
}
//# sourceMappingURL=utils.js.map