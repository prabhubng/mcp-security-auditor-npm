// INTENTIONALLY VULNERABLE - For testing mcp-security-auditor only!
// DO NOT use this code in production.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// secrets-api-key: Hardcoded API key
const API_KEY = "sk-ant-api03-FAKE_KEY_FOR_TESTING_1234567890abcdef";
const OPENAI_KEY = "sk-1234567890abcdefghijklmnopqrstuv";
const DB_URL = "mongodb+srv://admin:SuperSecret123@cluster0.example.net/mydb";

const server = new Server({ name: "vulnerable-test-server", version: "0.1.0" }, {
  capabilities: { tools: {} }
});

// static-eval: Dangerous eval usage
server.tool("execute_code", async ({ code }) => {
  const result = eval(code); // Critical: arbitrary code execution
  return { content: [{ type: "text", text: String(result) }] };
});

// injection-sql-inject: SQL injection via string concatenation
server.tool("query_db", async ({ table, filter }) => {
  const query = `SELECT * FROM ${table} WHERE ${filter}`;
  // const result = await db.query(query);
  return { content: [{ type: "text", text: query }] };
});

// injection-prompt-concat: Prompt injection  
server.tool("ask_ai", async ({ user_input }) => {
  const prompt = "You are a helpful assistant. " + user_input;
  return { content: [{ type: "text", text: prompt }] };
});

// static-command-exec: Command execution
import { exec } from "child_process";
server.tool("run_command", async ({ cmd }) => {
  return new Promise((resolve) => {
    exec(cmd, (err, stdout) => {
      resolve({ content: [{ type: "text", text: stdout || String(err) }] });
    });
  });
});

// network-insecure-http: Insecure HTTP
const endpoint = "http://api.external-service.com/data";

// network-tls-disabled: TLS verification disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// permissions-wildcard: Wildcard permissions
const permissions = "*";

// config-debug: Debug mode enabled
const debug = true;

// Start with bind to all interfaces
const transport = new StdioServerTransport();
server.connect(transport);
