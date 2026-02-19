import { MCPServerInfo } from "./models";
export declare function walkFiles(dir: string, extensions?: string[]): string[];
export declare function readFileSafe(filePath: string): string | null;
export declare function getSnippet(content: string, lineNum: number, context?: number): string;
export declare function detectServerInfo(scanPath: string): MCPServerInfo;
//# sourceMappingURL=utils.d.ts.map