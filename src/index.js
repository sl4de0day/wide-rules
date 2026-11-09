import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export * from "./decision/index.js";

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
  return { version: "0.2101126", totalRules: 0, rules: [] };
}
