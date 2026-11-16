export * from "./decision/index.js";

export interface SecurityRule {
  id: string;
  name: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  languages: string[];
  cwe?: string;
  cve?: string | string[];
  pattern: string;
  "not-match"?: string;
  "source-pattern"?: string;
  confidence?: "high" | "medium" | "low";
  message: string;
  why?: string;
  remediation?: string;
  instruction?: string;
  references?: string[];
  metadata?: {
    source?: string;
    kev?: boolean;
    epss?: number;
    learnedAt?: string;
    advisoryUrl?: string;
  };
  tests?: {
    positive?: string[];
    negative?: string[];
  };
}

export interface RulesBundle {
  version: string;
  generatedAt: string;
  totalRules: number;
  categories: Record<string, number>;
  severities: Record<string, number>;
  rules: SecurityRule[];
}

export interface AdvisoryEntry {
  name: string;
  ge?: string;
  lt?: string;
  le?: string;
  id: string;
  ghsaId?: string;
  cve?: string;
  cwe: string;
  sev: string;
  note: string;
  kev?: boolean;
  epss?: number;
}

export interface AdvisoriesBundle {
  version: number;
  generatedAt: string;
  sources: string[];
  stats: {
    total: number;
    kevCount: number;
    highEpssCount: number;
    byEcosystem: Record<string, number>;
  };
  npm: AdvisoryEntry[];
  pip: AdvisoryEntry[];
  maven: AdvisoryEntry[];
  go: AdvisoryEntry[];
  cargo: AdvisoryEntry[];
  nuget: AdvisoryEntry[];
  composer: AdvisoryEntry[];
  rubygems: AdvisoryEntry[];
}

export function getRulesPath(): string;
export function loadRules(): RulesBundle;
export function loadAgentRules(): SecurityRule[];
export function buildAgentInstructions(rules?: SecurityRule[]): string;
export function sanitizeAgentOutput(text: string, rules?: SecurityRule[]): string;
export function syncFromRemote(options?: Record<string, unknown>): Promise<{
  cacheDir: string;
  rulesPath: string;
  rulesCount: number;
  osvPath: string | null;
  osvCount: number;
  verifiedSha256: boolean;
  syncedAt: string;
}>;
export function syncAdvisoriesFromInternet(options?: Record<string, unknown>): Promise<{
  outFile: string;
  rawOutFile: string;
  fetchedAdvisories: number;
  kevMatched: number;
  added: number;
  updated: number;
  total: number;
  sources: string[];
}>;
export function loadAdvisories(options?: Record<string, unknown>): AdvisoriesBundle;
export function pruneAdvisoryDb(dbInput: AdvisoriesBundle, options?: { maxPerEcosystem?: number; maxTotal?: number }): {
  db: AdvisoriesBundle;
  prunedCount: number;
  archived: Array<AdvisoryEntry & { ecosystem: string }>;
};
export function queryOsvBatch(queries: Array<{ package: { ecosystem: string; name: string }; version: string }>, options?: Record<string, unknown>): Promise<Array<{ query: unknown; vulns: Array<{ id: string; modified?: string }> }>>;
export function checkRegexSafety(patternStr: string, options?: { strictStatic?: boolean; maxProbeMs?: number }): { safe: boolean; reason?: string; elapsedMs?: number };
export function verifyRuleCandidate(doc: unknown, options?: Record<string, unknown>): { ok: boolean; errors: string[]; warnings: string[]; falsePositives?: number };
export function learnRulesFromAdvisories(options?: Record<string, unknown>): Promise<{
  ok: boolean;
  provider?: string;
  reason?: string;
  candidatesConsidered?: number;
  learned: Array<{ id: string; ruleId: string; filePath: string }>;
  rejected: Array<{ id: string; reason: string }>;
}>;
