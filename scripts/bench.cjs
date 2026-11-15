const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");

const rootDir = path.resolve(__dirname, "..");
const bundlePath = path.join(rootDir, "dist", "rules.json");

function buildCorpusLines(count) {
  const sample = [
    "const user = req.body.username;",
    "app.get('/api/users/:id', async (req, res) => { return res.json({ ok: true }); });",
    "const rows = await db.query('SELECT id, name FROM users WHERE org_id = $1', [orgId]);",
    "export function formatTitle(value) { return String(value || '').trim(); }",
    "const tokenHash = crypto.createHash('sha256').update(input).digest('hex');",
    "subprocess.run(['git', 'status'], cwd=workspace_root, check=True)",
    "return Object.assign(Object.create(null), payload);"
  ];
  const lines = [];
  for (let i = 0; i < count; i++) lines.push(sample[i % sample.length]);
  return lines;
}

function main() {
  if (!fs.existsSync(bundlePath)) {
    console.error("Missing dist/rules.json; run npm run bundle first.");
    process.exit(1);
  }
  const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  const rules = Array.isArray(bundle.rules) ? bundle.rules : [];
  const compiled = [];
  for (const r of rules) {
    if (!r.pattern) continue;
    const flags = String(r.pattern).includes("\\uD800") ? "" : (r.flags || "");
    compiled.push({
      id: r.id,
      re: new RegExp(r.pattern, flags),
      nm: r["not-match"] ? new RegExp(r["not-match"], flags) : null
    });
  }

  const lines = buildCorpusLines(1000);
  const t0 = performance.now();
  let hits = 0;
  for (const line of lines) {
    for (const c of compiled) {
      if (c.re.test(line) && !(c.nm && c.nm.test(line))) hits++;
    }
  }
  const eval1kMs = performance.now() - t0;

  const adversarial = [
    "a".repeat(2000) + "!",
    " ".repeat(2000) + "!",
    "a.b.".repeat(500) + "!",
    "SELECT " + "id,".repeat(600) + " FROM users WHERE ",
    "<div " + "a='b' ".repeat(300) + "!"
  ];
  let worstProbeMs = 0;
  let worstRule = "";
  for (const c of compiled) {
    c.re.test("warmup_sample");
    for (const probe of adversarial) {
      const s = performance.now();
      c.re.test(probe);
      const dt = performance.now() - s;
      if (dt > worstProbeMs) {
        worstProbeMs = dt;
        worstRule = c.id;
      }
    }
  }

  console.log(JSON.stringify({
    rules: compiled.length,
    corpusLines: lines.length,
    hits,
    eval1kMs: Number(eval1kMs.toFixed(2)),
    worstProbeMs: Number(worstProbeMs.toFixed(2)),
    worstRule
  }, null, 2));
}

main();
