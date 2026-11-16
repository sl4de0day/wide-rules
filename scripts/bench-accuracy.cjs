const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const rootDir = path.resolve(__dirname, "..");
const bundlePath = path.join(rootDir, "dist", "rules.json");
const extToLang = {
  ".js": "js",
  ".ts": "ts",
  ".py": "py",
  ".go": "go",
  ".java": "java",
  ".php": "php",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".tf": "tf"
};

function loadFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!e.isFile()) continue;
    const lang = extToLang[path.extname(e.name).toLowerCase()];
    if (!lang) continue;
    out.push({
      file: path.relative(rootDir, path.join(dir, e.name)).replace(/\\/g, "/"),
      lang,
      content: fs.readFileSync(path.join(dir, e.name), "utf8")
    });
  }
  return out;
}

function scanCorpusWithRules(files, rules) {
  const hits = [];
  for (const f of files) {
    const lines = f.content.split(/\r?\n/);
    const applicable = rules.filter((r) => {
      const langs = r.languages || [];
      if (langs.includes("all")) {
        return !["json", "yaml", "yml", "tf"].includes(f.lang);
      }
      return langs.includes(f.lang);
    });
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      const windowSlice = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 6)).join("\n");
      const fileHead = lines.slice(0, Math.min(lines.length, 15)).join("\n");
      for (const r of applicable) {
        if (!r.pattern) continue;
        const re = new RegExp(r.pattern, r.flags || "");
        if (!re.test(line)) continue;
        if (r["not-match"]) {
          const nm = new RegExp(r["not-match"], r.flags || "");
          if (nm.test(line)) continue;
          if ((r.id.startsWith("wide/xxe-") || r.id.startsWith("wide/client-crypto-")) && (nm.test(windowSlice) || nm.test(fileHead))) {
            continue;
          }
        }
        hits.push({ file: f.file, line: i + 1, ruleId: r.id, category: r.category });
      }
    }
  }
  return hits;
}

async function main() {
  const analysis = await import(pathToFileURL(path.join(rootDir, "src", "index.js")).href);
  const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  const rules = Array.isArray(bundle.rules) ? bundle.rules : [];

  const cleanFiles = loadFiles(path.join(rootDir, "tests", "corpus", "clean"));
  const vulnFiles = loadFiles(path.join(rootDir, "tests", "corpus", "vulnerable"));

  const cleanRuleHits = scanCorpusWithRules(cleanFiles, rules);
  const cleanFlowHits = analysis.analyzeProjectFlows(cleanFiles);
  const vulnRuleHits = scanCorpusWithRules(vulnFiles, rules);
  const vulnFlowHits = analysis.analyzeProjectFlows(vulnFiles);

  const report = {
    cleanFiles: cleanFiles.length,
    cleanRuleHits: cleanRuleHits.length,
    cleanFlowHits: cleanFlowHits.length,
    vulnFiles: vulnFiles.length,
    vulnRuleHits: vulnRuleHits.length,
    vulnFlowHits: vulnFlowHits.length,
    crossFileHits: vulnFlowHits.filter((h) => h.crossFile).length,
    falsePositives: [...cleanRuleHits, ...cleanFlowHits]
  };
  console.log(JSON.stringify(report, null, 2));

  if (report.cleanRuleHits > 0 || report.cleanFlowHits > 0) {
    console.error("Accuracy gate failed: non-zero false positives on clean corpus.");
    process.exit(1);
  }
  if (report.vulnRuleHits === 0 || report.vulnFlowHits === 0 || report.crossFileHits === 0) {
    console.error("Accuracy gate failed: expected rule, taint, and cross-file detections on vulnerable corpus.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
