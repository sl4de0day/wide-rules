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

let cachedRulesState = { mtimeMs: -1, size: -1, data: null };
const agentEmojiRegexCache = new Map();

function getCachedAgentEmojiRegex(pattern, flags) {
  const key = `${pattern}\0${flags}`;
  let compiled = agentEmojiRegexCache.get(key);
  if (!compiled) {
    if (agentEmojiRegexCache.size >= 256) agentEmojiRegexCache.clear();
    compiled = new RegExp(pattern, flags);
    agentEmojiRegexCache.set(key, compiled);
  }
  compiled.lastIndex = 0;
  return compiled;
}

export function loadRules() {
  if (fs.existsSync(rulesJsonPath)) {
    const stat = fs.statSync(rulesJsonPath);
    if (
      cachedRulesState.data &&
      cachedRulesState.mtimeMs === stat.mtimeMs &&
      cachedRulesState.size === stat.size
    ) {
      return cachedRulesState.data;
    }
    const raw = fs.readFileSync(rulesJsonPath, "utf8");
    const parsed = JSON.parse(raw);
    cachedRulesState = { mtimeMs: stat.mtimeMs, size: stat.size, data: parsed };
    return parsed;
  }
  return { version: "0.4151126", totalRules: 0, rules: [] };
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

const EMOJI_ZWJ_SEQUENCE_RE = /(?:\p{Extended_Pictographic}|\p{Emoji_Presentation}|[\u2600-\u27BF])(?:\uFE0F|\uFE0E|[\u{1F3FB}-\u{1F3FF}])?(?:\u200D(?:\p{Extended_Pictographic}|\p{Emoji_Presentation}|[\u2600-\u27BF])(?:\uFE0F|\uFE0E|[\u{1F3FB}-\u{1F3FF}])?)+/gu;
const EMOJI_KEYCAP_RE = /[0-9#*]\uFE0F?\u20E3/gu;
const EMOJI_SUPP_RE = /[\u{1F1E6}-\u{1F1FF}\u{1F3FB}-\u{1F3FF}\u{E0020}-\u{E007F}]/gu;
const EMOJI_PICT_RE = /\p{Extended_Pictographic}(?:\uFE0F|\uFE0E)?/gu;
const EMOJI_PRES_RE = /\p{Emoji_Presentation}(?:\uFE0F|\uFE0E)?/gu;
const EMOJI_BMP_RE = /[\u231A-\u23FF\u2600-\u27BF\u2B05-\u2B55][\uFE0E\uFE0F]?|[\u2139\u2194-\u21AA\u24C2\u25AA-\u25FE\u2934-\u2935\u3030\u303D\u3297\u3299]\uFE0F|[\uFE0E\uFE0F\u20E3]/gu;
const LONE_SURROGATE_RE = new RegExp("[\\uD800-\\uDFFF]", "g");

function stripAllEmojis(text) {
  return text
    .replace(EMOJI_ZWJ_SEQUENCE_RE, "")
    .replace(EMOJI_KEYCAP_RE, "")
    .replace(EMOJI_SUPP_RE, "")
    .replace(EMOJI_PICT_RE, "")
    .replace(EMOJI_PRES_RE, "")
    .replace(EMOJI_BMP_RE, "")
    .replace(LONE_SURROGATE_RE, "");
}

export function sanitizeAgentOutput(text, rules) {
  if (!text || typeof text !== "string") return "";
  const targetRules = Array.isArray(rules) && rules.length > 0 ? rules : loadAgentRules();
  let result = stripAllEmojis(text);
  for (const r of targetRules) {
    if (r.id === "wide/ai-no-emojis" || (r.pattern && String(r.id || "").includes("emoji"))) {
      try {
        const flags = String(r.pattern || "").includes("\\uD800") ? "g" : "gu";
        const regex = getCachedAgentEmojiRegex(r.pattern, flags);
        result = result.replace(regex, "");
      } catch {
        void 0;
      }
    }
  }
  return result;
}
