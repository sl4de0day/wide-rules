import * as fs from "node:fs";
import * as path from "node:path";
import { checkRegexSafety } from "./redos.js";

const VALID_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
const VALID_CONFIDENCE = new Set(["high", "medium", "low"]);
const ID_RE = /^wide\/[a-z0-9_-]+$/;

export const DEFAULT_CLEAN_CORPUS = [
  { lang: "js", code: "const count = Number(req.query.count || 0);" },
  { lang: "js", code: "const rows = await pool.query('SELECT id, name FROM users WHERE id = $1', [userId]);" },
  { lang: "ts", code: "export function greet(name: string): string { return `Hello ${name}`; }" },
  { lang: "ts", code: "const safeUrl = new URL('/dashboard', window.location.origin);" },
  { lang: "py", code: "data = yaml.safe_load(raw_text)" },
  { lang: "py", code: "cursor.execute('SELECT * FROM items WHERE owner_id = %s', (user_id,))" },
  { lang: "go", code: "rows, err := db.QueryContext(ctx, \"SELECT id FROM items WHERE id = $1\", id)" },
  { lang: "java", code: "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();" },
  { lang: "php", code: "$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');" },
  { lang: "json", code: "{ \"name\": \"clean-app\", \"dependencies\": { \"next\": \"16.0.7\", \"express\": \"5.1.0\" } }" }
];

export function collectCleanCorpus(dirs = []) {
  const samples = [...DEFAULT_CLEAN_CORPUS];
  const extToLang = {
    ".js": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "ts",
    ".py": "py",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".tf": "tf",
    ".tfvars": "tf"
  };

  for (const dir of dirs) {
    if (!dir || !fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const lang = extToLang[path.extname(entry.name).toLowerCase()];
      if (!lang) continue;
      const lines = fs.readFileSync(path.join(dir, entry.name), "utf8").split(/\r?\n/);
      for (const line of lines.slice(0, 120)) {
        const trimmed = line.trim();
        if (trimmed && trimmed.length <= 240) {
          samples.push({ lang, code: line });
        }
      }
    }
  }
  return samples;
}

export function verifyRuleCandidate(doc, options = {}) {
  const errors = [];
  const warnings = [];

  if (!doc || typeof doc !== "object") {
    return { ok: false, errors: ["Candidate must be an object"], warnings };
  }
  if (!doc.id || !ID_RE.test(doc.id)) {
    errors.push(`Invalid id '${doc.id}': must match ^wide/[a-z0-9_-]+$`);
  }
  if (!doc.name || typeof doc.name !== "string") {
    errors.push("Missing rule name");
  }
  if (!doc.category || typeof doc.category !== "string") {
    errors.push("Missing rule category");
  }
  if (!VALID_SEVERITIES.has(doc.severity)) {
    errors.push(`Invalid severity '${doc.severity}'`);
  }
  if (!Array.isArray(doc.languages) || doc.languages.length === 0) {
    errors.push("languages must be a non-empty array");
  }
  if (!doc.message || typeof doc.message !== "string") {
    errors.push("Missing message");
  }
  if (doc.confidence && !VALID_CONFIDENCE.has(doc.confidence)) {
    errors.push(`Invalid confidence '${doc.confidence}'`);
  }

  const strictStatic = options.strictStatic !== false;
  const maxProbeMs = typeof options.maxProbeMs === "number" ? options.maxProbeMs : 15;
  const patternSafety = checkRegexSafety(doc.pattern, { strictStatic, maxProbeMs });
  if (!patternSafety.safe) {
    errors.push(`Unsafe pattern: ${patternSafety.reason}`);
  }

  if (doc["not-match"]) {
    const nmSafety = checkRegexSafety(doc["not-match"], { strictStatic, maxProbeMs });
    if (!nmSafety.safe) {
      errors.push(`Unsafe not-match: ${nmSafety.reason}`);
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const patternRe = new RegExp(doc.pattern, doc.flags || "");
  const notMatchRe = doc["not-match"] ? new RegExp(doc["not-match"], doc.flags || "") : null;
  const matchesRule = (line) => patternRe.test(line) && !(notMatchRe && notMatchRe.test(line));

  const requireTests = options.requireTests !== false;
  const posCases = Array.isArray(doc.tests?.positive) ? doc.tests.positive : [];
  const negCases = Array.isArray(doc.tests?.negative) ? doc.tests.negative : [];

  if (requireTests && posCases.length < 1) {
    errors.push("Candidate must include at least 1 positive test case");
  }
  if (requireTests && negCases.length < 1) {
    errors.push("Candidate must include at least 1 negative test case");
  }

  for (let i = 0; i < posCases.length; i++) {
    const sample = String(posCases[i]);
    if (!patternRe.test(sample)) {
      errors.push(`Positive sample #${i + 1} did not match pattern`);
    } else if (notMatchRe && notMatchRe.test(sample)) {
      errors.push(`Positive sample #${i + 1} was suppressed by not-match`);
    }
  }

  for (let i = 0; i < negCases.length; i++) {
    const sample = String(negCases[i]);
    if (matchesRule(sample)) {
      errors.push(`Negative sample #${i + 1} produced a false positive match`);
    }
  }

  const langs = new Set(doc.languages || []);
  const isCodeLang = ![...langs].every((l) => ["json", "yaml", "yml", "toml", "xml"].includes(l));
  if (isCodeLang && posCases.length > 0) {
    const commentSample = `// ${String(posCases[0]).trim()}`;
    if (matchesRule(commentSample)) {
      warnings.push("Candidate matches inside '//' comments; ensure engine comment filter or not-match handles comments");
    }
  }

  const corpus = Array.isArray(options.corpus) ? options.corpus : DEFAULT_CLEAN_CORPUS;
  const maxFalsePositives = typeof options.maxFalsePositives === "number" ? options.maxFalsePositives : 0;
  let falsePositives = 0;
  for (const item of corpus) {
    if (!langs.has("all") && !langs.has(item.lang)) continue;
    if (matchesRule(item.code)) {
      falsePositives++;
    }
  }
  if (falsePositives > maxFalsePositives) {
    errors.push(`Candidate exceeded false-positive budget on clean corpus (${falsePositives} > ${maxFalsePositives})`);
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    falsePositives
  };
}
