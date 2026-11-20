const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { stripTypeScriptTypes } = require("node:module");

const ROOT = path.resolve(__dirname, "..");
const SRC_DIR = path.join(ROOT, "engine", "src");
const LIB_DIR = path.join(ROOT, "engine", "lib");
const CONFORMANCE_DIR = path.join(ROOT, "engine", "conformance");
const CASES_FILE = path.join(CONFORMANCE_DIR, "cases.json");
const SUITE_FILE = path.join(CONFORMANCE_DIR, "suite.json");
const CORPUS_DIR = path.join(ROOT, "tests", "corpus");
const CORPUS_LANG = { js: "js", ts: "ts", py: "py", go: "go", php: "php", java: "java", tf: "tf", yml: "yml", yaml: "yaml" };
const checkOnly = process.argv.includes("--check");

process.removeAllListeners("warning");
process.on("warning", (w) => {
  if (w.name !== "ExperimentalWarning") console.warn(w);
});

function normalizeText(text) {
  return String(text).replace(/\r\n/g, "\n");
}

function expectedLib() {
  const out = new Map();
  for (const name of fs.readdirSync(SRC_DIR).filter((f) => f.endsWith(".ts")).sort()) {
    const source = normalizeText(fs.readFileSync(path.join(SRC_DIR, name), "utf8"));
    const js = stripTypeScriptTypes(source, { mode: "strip" })
      .split("\n")
      .map((line) => line.replace(/\s+$/, ""))
      .join("\n")
      .replace(/\n{3,}/g, "\n\n")
      .replace(/^\s*\n/, "")
      .replace(/\n*$/, "\n");
    out.set(name.replace(/\.ts$/, ".js"), js);
  }
  return out;
}

function corpusProjects() {
  const projects = [];
  for (const kind of ["clean", "vulnerable"]) {
    const dir = path.join(CORPUS_DIR, kind);
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).sort()
      .map((name) => ({ name, ext: name.split(".").pop().toLowerCase() }))
      .filter((f) => CORPUS_LANG[f.ext])
      .map((f) => ({ file: `${kind}/${f.name}`, lang: CORPUS_LANG[f.ext], content: normalizeText(fs.readFileSync(path.join(dir, f.name), "utf8")) }));
    projects.push({ name: `corpus-${kind}`, files });
  }
  return projects;
}

function corpusSecretLines(projects) {
  const lines = [];
  for (const project of projects) {
    for (const f of project.files) {
      for (const line of f.content.split("\n")) {
        if (/(?:key|token|secret|password|passwd|AKIA|ghp_|sk-)/i.test(line) && /["'`=:]/.test(line)) {
          lines.push({ file: f.file, line });
        }
      }
    }
  }
  return lines;
}

function toConformanceFinding(f) {
  return {
    ruleId: f.ruleId,
    cwe: f.cwe,
    category: f.category,
    severity: f.severity,
    file: f.file,
    line: f.line,
    endLine: f.endLine,
    message: f.message,
    snippet: f.snippet,
    crossFile: f.crossFile === true
  };
}

async function buildSuite(libDir) {
  const engine = await import(pathToFileURL(path.join(libDir, "index.js")).href);
  const cases = JSON.parse(fs.readFileSync(CASES_FILE, "utf8"));
  const corpus = corpusProjects();
  const projects = [...cases.projects, ...corpus].map((p) => ({
    name: p.name,
    files: p.files,
    expected: engine.analyzeProjectFlows(p.files).map(toConformanceFinding)
  }));
  const secrets = [...cases.secrets, ...corpusSecretLines(corpus)].map((s) => ({
    file: s.file,
    line: s.line,
    expected: engine.isLikelyRealSecret(s.line, s.file)
  }));
  return `${JSON.stringify({ projects, secrets }, null, 2)}\n`;
}

async function main() {
  const lib = expectedLib();

  if (checkOnly) {
    const problems = [];
    const present = fs.existsSync(LIB_DIR) ? fs.readdirSync(LIB_DIR).filter((f) => f.endsWith(".js")) : [];
    for (const [name, js] of lib) {
      const target = path.join(LIB_DIR, name);
      if (!fs.existsSync(target)) problems.push(`missing lib/${name}`);
      else if (normalizeText(fs.readFileSync(target, "utf8")) !== js) problems.push(`stale lib/${name}`);
    }
    for (const name of present) {
      if (!lib.has(name)) problems.push(`orphan lib/${name}`);
    }
    if (problems.length === 0) {
      const suite = await buildSuite(LIB_DIR);
      if (!fs.existsSync(SUITE_FILE)) problems.push("missing conformance/suite.json");
      else if (normalizeText(fs.readFileSync(SUITE_FILE, "utf8")) !== suite) problems.push("stale conformance/suite.json");
    }
    if (problems.length > 0) {
      console.error(`[engine] out of date: ${problems.join(", ")}. Run npm run build:engine.`);
      process.exit(1);
    }
    console.log(`[engine] engine/lib (${lib.size} modules) and conformance suite are up to date.`);
    return;
  }

  fs.rmSync(LIB_DIR, { recursive: true, force: true });
  fs.mkdirSync(LIB_DIR, { recursive: true });
  for (const [name, js] of lib) {
    fs.writeFileSync(path.join(LIB_DIR, name), js);
  }
  const suite = await buildSuite(LIB_DIR);
  fs.writeFileSync(SUITE_FILE, suite);
  const parsed = JSON.parse(suite);
  const findings = parsed.projects.reduce((n, p) => n + p.expected.length, 0);
  console.log(`[engine] wrote ${lib.size} modules to engine/lib and conformance suite (${parsed.projects.length} projects, ${findings} findings, ${parsed.secrets.length} secret cases).`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
