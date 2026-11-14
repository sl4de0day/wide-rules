import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export * from "./decision/index.js";
export * from "./feeds/sources.js";
export * from "./updater/sync.js";
export * from "./learning/redos.js";
export * from "./learning/verifier.js";
export * from "./learning/synthesizer.js";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const rulesJsonPath = path.resolve(currentDir, "../dist/rules.json");

export function getRulesPath() {
  return rulesJsonPath;
}

export function loadRules() {
  if (fs.existsSync(rulesJsonPath)) {
    const raw = fs.readFileSync(rulesJsonPath, "utf8");
    return JSON.parse(raw);
  }
  return { version: "0.3141126", totalRules: 0, rules: [] };
}

export function loadAgentRules() {
  const bundle = loadRules();
  const list = Array.isArray(bundle) ? bundle : (bundle.rules || []);
  return list.filter((r) => r && (r.category === "AI_SECURITY" || String(r.id).includes("ai-")));
}

export function buildAgentInstructions(rules) {
  const targetRules = Array.isArray(rules) && rules.length > 0 ? rules : loadAgentRules();
  const instructions = [];
  for (const r of targetRules) {
    const text = (r.instruction || r.message || "").trim();
    if (text) {
      instructions.push(`- ${text}`);
    }
  }
  return instructions.join("\n");
}

export function sanitizeAgentOutput(text, rules) {
  if (!text || typeof text !== "string") return "";
  const targetRules = Array.isArray(rules) && rules.length > 0 ? rules : loadAgentRules();
  let result = text;
  for (const r of targetRules) {
    if (r.id === "wide/ai-no-emojis" || (r.pattern && r.id.includes("emoji"))) {
      try {
        const regex = new RegExp(r.pattern, "gu");
        result = result.replace(regex, "");
      } catch {
        result = result.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]|[\u2600-\u27BF]/g, "");
      }
    }
  }
  return result;
}
