export * from "./decision/index.js";

export interface SecurityRule {
  id: string;
  name: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  languages: string[];
  cwe?: string;
  pattern: string;
  "not-match"?: string;
  confidence?: "high" | "medium" | "low";
  message: string;
  why?: string;
  remediation?: string;
  instruction?: string;
}

export interface RulesBundle {
  version: string;
  generatedAt: string;
  totalRules: number;
  categories: Record<string, number>;
  severities: Record<string, number>;
  rules: SecurityRule[];
}

export function getRulesPath(): string;
export function loadRules(): RulesBundle;
export function loadAgentRules(): SecurityRule[];
export function buildAgentInstructions(rules?: SecurityRule[]): string;
export function sanitizeAgentOutput(text: string, rules?: SecurityRule[]): string;
