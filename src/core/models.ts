// Core types and interfaces for MCP Security Auditor

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "static-code"
  | "permissions"
  | "network"
  | "dependencies"
  | "injection"
  | "configuration"
  | "secrets";

export interface CodeLocation {
  file: string;
  line: number;
  column?: number;
  snippet?: string;
}

export interface Remediation {
  description: string;
  effort: "low" | "medium" | "high";
  reference?: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  location?: CodeLocation;
  remediation?: Remediation;
  confidence: "high" | "medium" | "low";
  cwe?: string;
  tags?: string[];
}

export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

export interface MCPServerInfo {
  name: string;
  version?: string;
  description?: string;
  tools: ToolDefinition[];
  language: "typescript" | "python" | "javascript" | "unknown";
  framework?: string;
  transportType?: "stdio" | "sse" | "http" | "unknown";
  entryPoint?: string;
  configFiles: string[];
  sourceFiles: string[];
}

export interface ScanResult {
  serverInfo: MCPServerInfo;
  findings: Finding[];
  scanDuration: number;
  timestamp: string;
  version: string;
  summary: ScanSummary;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  categories: Record<FindingCategory, number>;
}

export type ReportFormat = "text" | "json" | "sarif" | "html" | "markdown";

export interface ScanOptions {
  path: string;
  format: ReportFormat;
  output?: string;
  failOn?: Severity;
  analyzers?: string[];
  verbose?: boolean;
  noColor?: boolean;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const VERSION = "1.0.0";
