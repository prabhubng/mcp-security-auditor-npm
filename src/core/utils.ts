import * as fs from "fs";
import * as path from "path";
import { MCPServerInfo, ToolDefinition } from "./models";

const IGNORE_DIRS = new Set([
  "node_modules", ".git", "__pycache__", ".venv", "venv",
  "dist", "build", ".next", ".nuxt", "coverage", ".tox",
  "env", ".env", ".mypy_cache", ".pytest_cache", "egg-info",
]);

const SOURCE_EXTENSIONS: Record<string, "typescript" | "javascript" | "python"> = {
  ".ts": "typescript", ".tsx": "typescript",
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
  ".py": "python",
};

export function walkFiles(dir: string, extensions?: string[]): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  function walk(currentDir: string) {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(currentDir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (entry.name.startsWith(".") && entry.isDirectory()) continue;
      if (IGNORE_DIRS.has(entry.name) && entry.isDirectory()) continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
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

export function readFileSafe(filePath: string): string | null {
  try { return fs.readFileSync(filePath, "utf-8"); }
  catch { return null; }
}

export function getSnippet(content: string, lineNum: number, context = 2): string {
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

export function detectServerInfo(scanPath: string): MCPServerInfo {
  const info: MCPServerInfo = {
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
  const langCount: Record<string, number> = {};
  for (const f of info.sourceFiles) {
    const ext = path.extname(f).toLowerCase();
    const lang = SOURCE_EXTENSIONS[ext];
    if (lang) langCount[lang] = (langCount[lang] || 0) + 1;
  }
  const topLang = Object.entries(langCount).sort((a, b) => b[1] - a[1])[0];
  if (topLang) info.language = topLang[0] as MCPServerInfo["language"];

  // Detect framework and transport from package.json
  const pkgJsonPath = path.join(scanPath, "package.json");
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
      info.name = pkg.name || info.name;
      info.version = pkg.version;
      info.description = pkg.description;
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (allDeps["@modelcontextprotocol/sdk"]) info.framework = "mcp-sdk";
      if (allDeps["fastmcp"]) info.framework = "fastmcp";
      if (pkg.main) info.entryPoint = pkg.main;
    } catch { /* skip */ }
  }

  // Detect framework from pyproject.toml
  const pyprojectPath = path.join(scanPath, "pyproject.toml");
  if (fs.existsSync(pyprojectPath)) {
    const content = readFileSafe(pyprojectPath);
    if (content) {
      if (content.includes("mcp")) info.framework = "mcp-python-sdk";
      if (content.includes("fastmcp")) info.framework = "fastmcp";
      const nameMatch = content.match(/name\s*=\s*"([^"]+)"/);
      if (nameMatch) info.name = nameMatch[1];
      const verMatch = content.match(/version\s*=\s*"([^"]+)"/);
      if (verMatch) info.version = verMatch[1];
    }
  }

  // Detect tools from source code
  info.tools = detectTools(info.sourceFiles);

  // Detect transport
  for (const f of info.sourceFiles) {
    const content = readFileSafe(f);
    if (!content) continue;
    if (/StdioServerTransport|stdio_server|transport.*stdio/i.test(content)) {
      info.transportType = "stdio";
    } else if (/SSEServerTransport|sse_server|transport.*sse/i.test(content)) {
      info.transportType = "sse";
    } else if (/StreamableHTTPServerTransport|http_server/i.test(content)) {
      info.transportType = "http";
    }
    if (info.transportType) break;
  }

  return info;
}

function detectTools(sourceFiles: string[]): ToolDefinition[] {
  const tools: ToolDefinition[] = [];
  const seen = new Set<string>();

  for (const f of sourceFiles) {
    const content = readFileSafe(f);
    if (!content) continue;

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
