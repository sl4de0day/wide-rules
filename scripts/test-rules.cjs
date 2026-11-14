const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const assert = require('node:assert/strict');
const { pathToFileURL } = require('url');

const rootDir = path.resolve(__dirname, '..');
const bundlePath = path.join(rootDir, 'dist', 'rules.json');

async function main() {
  if (!fs.existsSync(bundlePath)) {
    console.error('ERROR: dist/rules.json does not exist. Run bundle first.');
    process.exit(1);
  }

  const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
  console.log(`Testing bundle version ${bundle.version} with ${bundle.totalRules} rules...`);

  assert.ok(bundle.totalRules >= 725, `Expected at least 725 rules, got ${bundle.totalRules}`);
  assert.equal(bundle.totalRules, bundle.rules.length);

  let testedRegexCount = 0;
  for (const rule of bundle.rules) {
    assert.ok(rule.id.startsWith('wide/'));
    assert.ok(rule.pattern.length > 0);
    const regex = new RegExp(rule.pattern, 'i');
    assert.ok(regex instanceof RegExp);
    if (rule['not-match']) {
      const nm = new RegExp(rule['not-match'], 'i');
      assert.ok(nm instanceof RegExp);
    }
    testedRegexCount++;
  }
  console.log(`Verified ${testedRegexCount} compiled regular expressions.`);

  const jsConcatRule = bundle.rules.find(r => r.id === 'wide/cwe89-js-query-concat');
  assert.ok(jsConcatRule);
  assert.ok(new RegExp(jsConcatRule.pattern, 'i').test('db.query("SELECT * FROM users WHERE id = " + id)'));

  const jsTemplateRule = bundle.rules.find(r => r.id === 'wide/cwe89-js-query-template-literal');
  assert.ok(jsTemplateRule);
  assert.ok(new RegExp(jsTemplateRule.pattern, 'i').test('db.query(`SELECT * FROM users WHERE id = ${id}`)'));

  const pyFstringRule = bundle.rules.find(r => r.id === 'wide/cwe89-py-execute-fstring');
  assert.ok(pyFstringRule);
  assert.ok(new RegExp(pyFstringRule.pattern, 'i').test('cursor.execute(f"SELECT * FROM users WHERE id = {val}")'));

  const csCommandRule = bundle.rules.find(r => r.id === 'wide/cwe89-cs-command-concat');
  assert.ok(csCommandRule);
  assert.ok(new RegExp(csCommandRule.pattern, 'i').test('new SqlCommand("SELECT * FROM users WHERE id = " + id)'));

  const dbRuleChecks = [
    {
      id: 'wide/cwe89-prisma-raw-unsafe',
      pos: ['prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`)'],
      neg: ['prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`']
    },
    {
      id: 'wide/cwe89-drizzle-sql-raw',
      pos: ['db.execute(sql.raw(`SELECT * FROM users WHERE id = ${userId}`))'],
      neg: ['db.execute(sql`SELECT * FROM users WHERE id = ${userId}`)', "sql.raw('SELECT 1')"]
    },
    {
      id: 'wide/cwe89-sequelize-literal',
      pos: ['User.findAll({ order: Sequelize.literal(`id ${dir}`) })'],
      neg: ["User.create({ updatedAt: Sequelize.literal('CURRENT_TIMESTAMP') })"]
    },
    {
      id: 'wide/cwe943-mongoose-where-string-operator',
      pos: ['User.find({ $where: `this.name === "${name}"` })'],
      neg: ['User.find({ name: String(name) })']
    },
    {
      id: 'wide/cwe319-postgres-sslmode-disable',
      pos: ['const pg = "postgres://app:pw@db.internal:5432/app?sslmode=disable";'],
      neg: ['const pg = "postgres://app@db.internal:5432/app?sslmode=verify-full";']
    },
    {
      id: 'wide/tls-verification-off',
      pos: ['new Pool({ connectionString, ssl: { rejectUnauthorized: false } })'],
      neg: ['new Pool({ connectionString, ssl: { rejectUnauthorized: true } })']
    },
    {
      id: 'wide/cwe798-hardcoded-db-uri',
      pos: ['const uri = "postgresql://prod_admin:S3cur3ProdPass99@db.internal:5432/app";'],
      neg: ['const dev = "postgres://dev:devpass@localhost:5432/local_db";']
    }
  ];
  for (const chk of dbRuleChecks) {
    const rule = bundle.rules.find(r => r.id === chk.id);
    assert.ok(rule, `Missing DB security rule ${chk.id}`);
    const re = new RegExp(rule.pattern, 'i');
    const nm = rule['not-match'] ? new RegExp(rule['not-match'], 'i') : null;
    for (const sample of chk.pos) {
      assert.ok(re.test(sample) && !(nm && nm.test(sample)), `Rule ${chk.id} failed to match positive sample: ${sample}`);
    }
    for (const sample of chk.neg) {
      const matched = re.test(sample) && !(nm && nm.test(sample));
      assert.ok(!matched, `Rule ${chk.id} false-matched negative sample: ${sample}`);
    }
  }

  const aiPromptInjRule = bundle.rules.find(r => r.id === 'wide/cwe079-ai-prompt-injection');
  assert.ok(aiPromptInjRule);
  assert.ok(new RegExp(aiPromptInjRule.pattern, 'i').test('const prompt = `System instructions: ${req.body.input}`;'));

  const aiToolExecRule = bundle.rules.find(r => r.id === 'wide/cwe078-ai-unsafe-tool-exec');
  assert.ok(aiToolExecRule);
  assert.ok(new RegExp(aiToolExecRule.pattern, 'i').test('exec(toolCall.arguments.command);'));

  const aiNoEmojisRule = bundle.rules.find(r => r.id === 'wide/ai-no-emojis');
  assert.ok(aiNoEmojisRule);
  assert.ok(aiNoEmojisRule.instruction.includes('Do not use emojis'));
  const aiNoEmojisRegex = new RegExp(aiNoEmojisRule.pattern);
  assert.ok(aiNoEmojisRegex.test('Hello 😀 World'));
  assert.ok(!aiNoEmojisRegex.test('Hello World'));

  const aiNoLeakRule = bundle.rules.find(r => r.id === 'wide/ai-no-system-prompt-leak');
  assert.ok(aiNoLeakRule);
  assert.ok(aiNoLeakRule.instruction.includes('Never cite, quote'));
  assert.ok(new RegExp(aiNoLeakRule.pattern, 'i').test('my system prompt is confidential'));

  for (const reqId of ['wide/ai-direct-file-edits', 'wide/ai-native-tool-priority', 'wide/ai-language-matching']) {
    const r = bundle.rules.find(rule => rule.id === reqId);
    assert.ok(r, `Missing expected AI rule ${reqId}`);
    assert.ok(r.instruction && r.instruction.length > 20, `Missing instruction on ${reqId}`);
  }

  const mod = await import(pathToFileURL(path.join(rootDir, 'src', 'index.js')).href);

  const unsafeRes = mod.checkRegexSafety('^([a-z]+)+$', { strictStatic: true, maxProbeMs: 15 });
  assert.equal(unsafeRes.safe, false, 'ReDoS pattern should be rejected');

  const safeRes = mod.checkRegexSafety('unsafeCall\\([^)]*req\\.body', { strictStatic: true });
  assert.equal(safeRes.safe, true);

  const goodCandidate = {
    id: 'wide/vuln-cve-2026-99999',
    name: 'vuln-cve-2026-99999',
    category: 'NETWORK',
    severity: 'CRITICAL',
    languages: ['js', 'ts'],
    cwe: 'CWE-287',
    cve: 'CVE-2026-99999',
    pattern: "x-middleware-subrequest['\"]?\\s*\\]?\\s*[:=]",
    'not-match': '^\\s*(?://|/\\*|\\*)',
    message: 'Dangerous x-middleware-subrequest bypass trust detected.',
    tests: {
      positive: ["req.headers['x-middleware-subrequest'] = '1';"],
      negative: ["req.headers['x-request-id'] = id;"]
    }
  };
  assert.equal(mod.verifyRuleCandidate(goodCandidate).ok, true);

  const badCandidate = {
    ...goodCandidate,
    pattern: 'const\\s+[a-z]+'
  };
  assert.equal(mod.verifyRuleCandidate(badCandidate).ok, false, 'Over-broad pattern must fail corpus false-positive check');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wide-rules-sync-test-'));
  try {
    const advisoryOut = path.join(tmpDir, 'osv-advisories.json');
    const rawOut = path.join(tmpDir, 'raw-advisories.json');
    const mockFetch = async (url) => {
      const s = String(url);
      if (s.includes('api.github.com/advisories')) {
        return {
          ok: true,
          status: 200,
          json: async () => ([
            {
              ghsa_id: 'GHSA-xxxx-1111-2222',
              cve_id: 'CVE-2026-42424',
              severity: 'critical',
              summary: 'Demo middleware auth bypass',
              description: 'Demo advisory description',
              html_url: 'https://github.com/advisories/GHSA-xxxx-1111-2222',
              references: ['https://github.com/vercel/next.js/commit/0123456789abcdef0123456789abcdef01234567'],
              cwes: [{ cwe_id: 'CWE-287' }],
              vulnerabilities: [
                {
                  package: { ecosystem: 'npm', name: 'demo-pkg' },
                  vulnerable_version_range: '>= 1.0.0, < 1.2.5',
                  first_patched_version: '1.2.5'
                }
              ]
            }
          ])
        };
      }
      if (s.includes('known_exploited_vulnerabilities.json')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            catalogVersion: '2026.11.14',
            vulnerabilities: [{ cveID: 'CVE-2026-42424', vulnerabilityName: 'Demo Auth Bypass' }]
          })
        };
      }
      if (s.includes('api.first.org/data/v1/epss')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: [{ cve: 'CVE-2026-42424', epss: '0.8421', percentile: '0.99' }]
          })
        };
      }
      if (s.includes('/repos/vercel/next.js/commits/')) {
        return { ok: true, status: 200, text: async () => 'diff --git a/mw.js b/mw.js\n- skipAuth(req)\n+ verifyAuth(req)\n' };
      }
      throw new Error(`Unexpected URL: ${s}`);
    };

    const syncRes = await mod.syncAdvisoriesFromInternet({
      outFile: advisoryOut,
      rawOutFile: rawOut,
      fetchImpl: mockFetch
    });
    assert.equal(syncRes.total, 1);
    assert.equal(syncRes.kevMatched, 1);
    assert.equal(syncRes.db.npm[0].name, 'demo-pkg');
    assert.equal(syncRes.db.npm[0].kev, true);
    assert.equal(syncRes.db.npm[0].epss, 0.8421);

    const learnRes = await mod.learnRulesFromAdvisories({
      rawAdvisoriesFile: rawOut,
      outDir: path.join(tmpDir, 'learned'),
      stateFile: path.join(tmpDir, 'learned-state.json'),
      fetchImpl: mockFetch,
      completeFn: async () => ({
        category: 'AUTH',
        severity: 'CRITICAL',
        languages: ['js', 'ts'],
        pattern: 'skipAuth\\s*\\(\\s*req',
        'not-match': '^\\s*(?://|/\\*)',
        confidence: 'high',
        message: 'Unauthenticated bypass via skipAuth(req).',
        why: 'Auth validation was bypassed before request handling.',
        remediation: 'Use verifyAuth(req) instead of skipAuth(req).',
        tests: {
          positive: ['skipAuth(req);'],
          negative: ['verifyAuth(req);']
        }
      })
    });
    assert.equal(learnRes.ok, true);
    assert.equal(learnRes.learned.length, 1);
    assert.ok(fs.existsSync(learnRes.learned[0].filePath));

    const cacheDir = path.join(tmpDir, 'cache');
    const mockRulesBody = JSON.stringify({ version: '0.3141126', rules: [goodCandidate] });
    const mockOsvBody = JSON.stringify(syncRes.db);
    const rulesSha = crypto.createHash('sha256').update(mockRulesBody).digest('hex');
    const osvSha = crypto.createHash('sha256').update(mockOsvBody).digest('hex');
    const sumsBody = `${rulesSha}  rules.json\n${osvSha}  osv-bundle.json\n`;

    const remoteRes = await mod.syncFromRemote({
      cacheDir,
      verifySha256: true,
      fetchImpl: async (url) => {
        const s = String(url);
        if (s.endsWith('SHA256SUMS')) return { ok: true, status: 200, text: async () => sumsBody };
        if (s.endsWith('rules.json')) return { ok: true, status: 200, text: async () => mockRulesBody };
        if (s.endsWith('osv-bundle.json')) return { ok: true, status: 200, text: async () => mockOsvBody };
        throw new Error(`Unexpected remote URL: ${s}`);
      }
    });
    assert.equal(remoteRes.verifiedSha256, true);
    assert.equal(remoteRes.rulesCount, 1);
    assert.equal(remoteRes.osvCount, 1);

    await assert.rejects(() => mod.syncFromRemote({
      cacheDir,
      verifySha256: true,
      fetchImpl: async (url) => {
        const s = String(url);
        if (s.endsWith('SHA256SUMS')) return { ok: true, status: 200, text: async () => sumsBody };
        if (s.endsWith('rules.json')) return { ok: true, status: 200, text: async () => '{"tampered":true}' };
        throw new Error(`Unexpected remote URL: ${s}`);
      }
    }), /SHA-256 mismatch/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log('All rule engine and dynamic learning tests passed successfully.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
