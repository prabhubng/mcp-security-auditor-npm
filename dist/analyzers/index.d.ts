import { Finding, MCPServerInfo, FindingCategory, Severity } from "../core/models";
export declare abstract class BaseAnalyzer {
    abstract name: string;
    abstract category: FindingCategory;
    abstract analyze(scanPath: string, info: MCPServerInfo): Finding[];
    protected finding(id: string, title: string, description: string, severity: Severity, file?: string, line?: number, content?: string, extra?: Partial<Finding>): Finding;
    protected scanFilesByPattern(files: string[], patterns: Array<{
        pattern: RegExp;
        id: string;
        title: string;
        desc: string;
        severity: Severity;
        cwe?: string;
    }>): Finding[];
}
export declare class SecretsAnalyzer extends BaseAnalyzer {
    name: string;
    category: FindingCategory;
    private patterns;
    analyze(scanPath: string, info: MCPServerInfo): Finding[];
}
export declare class StaticCodeAnalyzer extends BaseAnalyzer {
    name: string;
    category: FindingCategory;
    private patterns;
    analyze(scanPath: string, info: MCPServerInfo): Finding[];
}
export declare class InjectionAnalyzer extends BaseAnalyzer {
    name: string;
    category: FindingCategory;
    private patterns;
    analyze(scanPath: string, info: MCPServerInfo): Finding[];
}
export declare class PermissionsAnalyzer extends BaseAnalyzer {
    name: string;
    category: FindingCategory;
    analyze(scanPath: string, info: MCPServerInfo): Finding[];
}
export declare class NetworkAnalyzer extends BaseAnalyzer {
    name: string;
    category: FindingCategory;
    private patterns;
    analyze(scanPath: string, info: MCPServerInfo): Finding[];
}
export declare class ConfigurationAnalyzer extends BaseAnalyzer {
    name: string;
    category: FindingCategory;
    analyze(scanPath: string, info: MCPServerInfo): Finding[];
}
export declare class DependenciesAnalyzer extends BaseAnalyzer {
    name: string;
    category: FindingCategory;
    private suspiciousPackages;
    private popularPackages;
    analyze(scanPath: string, info: MCPServerInfo): Finding[];
}
export declare const ANALYZERS: Record<string, new () => BaseAnalyzer>;
export declare function createAllAnalyzers(): BaseAnalyzer[];
export declare function createAnalyzers(names: string[]): BaseAnalyzer[];
//# sourceMappingURL=index.d.ts.map