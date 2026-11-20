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
  for (const sample of ['Hello 😀 World', 'Star ⭐', 'Info ℹ️', 'Keycap 1️⃣', 'Alarm ⏰']) {
    assert.ok(aiNoEmojisRegex.test(sample), `Regex missed emoji sample: ${sample}`);
  }
  assert.ok(!aiNoEmojisRegex.test('Hello World 1 + 2 -> 3'));

  const mod = await import(pathToFileURL(path.join(rootDir, 'src', 'index.js')).href);
  assert.equal(mod.sanitizeAgentOutput('Hello 😀⭐ℹ️1️⃣👨‍💻🇷🇺 World'), 'Hello  World');
  assert.equal(mod.sanitizeAgentOutput('Clean prose 1 + 2 -> 3'), 'Clean prose 1 + 2 -> 3');

  const aiNoLeakRule = bundle.rules.find(r => r.id === 'wide/ai-no-system-prompt-leak');
  assert.ok(aiNoLeakRule);
  assert.ok(aiNoLeakRule.instruction.includes('Never cite, quote'));
  assert.ok(new RegExp(aiNoLeakRule.pattern, 'i').test('my system prompt is confidential'));

  for (const reqId of ['wide/ai-direct-file-edits', 'wide/ai-native-tool-priority', 'wide/ai-language-matching']) {
    const r = bundle.rules.find(rule => rule.id === reqId);
    assert.ok(r, `Missing expected AI rule ${reqId}`);
    assert.ok(r.instruction && r.instruction.length > 20, `Missing instruction on ${reqId}`);
  }

  const unsafeRes = mod.checkRegexSafety('^([a-z]+)+$', { strictStatic: true, maxProbeMs: 15 });
  assert.equal(unsafeRes.safe, false, 'ReDoS pattern should be rejected');
  assert.equal(mod.checkRegexSafety('(?:.*foo){2,}', { strictStatic: true }).safe, false);
  assert.equal(mod.checkRegexSafety('(a+)\\1+', { strictStatic: true }).safe, false);
  assert.equal(mod.checkRegexSafety('(["\'])\\/{1,2}(?:(?!\\1).)*\\[(?:(?!\\1).)*=(?:(?!\\1).)*\\1', { strictStatic: true }).safe, false);
  assert.equal(mod.checkRegexSafety('(["\'])[^\'"]{6,}\\1', { strictStatic: true }).safe, true);
  assert.equal(mod.normalizeEcosystem('rust'), 'cargo');

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
    assert.equal(syncRes.changed, true);
    assert.equal(syncRes.kevMatched, 1);
    assert.equal(syncRes.db.npm[0].name, 'demo-pkg');
    assert.equal(syncRes.db.npm[0].kev, true);
    assert.equal(syncRes.db.npm[0].epss, 0.8421);

    const repeatSync = await mod.syncAdvisoriesFromInternet({
      outFile: advisoryOut,
      rawOutFile: rawOut,
      fetchImpl: mockFetch
    });
    assert.equal(repeatSync.changed, false);
    assert.equal(repeatSync.db.generatedAt, syncRes.db.generatedAt);

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
    const mockRulesBody = JSON.stringify({ version: '0.6211126', rules: [goodCandidate] });
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

    await assert.rejects(() => mod.syncFromRemote({
      cacheDir,
      verifySha256: true,
      fetchImpl: async (url) => {
        const s = String(url);
        if (s.endsWith('SHA256SUMS')) return { ok: false, status: 404, text: async () => '' };
        throw new Error(`Unexpected remote URL: ${s}`);
      }
    }), /SHA256SUMS/);

    const advOut2 = path.join(tmpDir, 'osv-advisories-2.json');
    const rawOut2 = path.join(tmpDir, 'raw-advisories-2.json');
    let phase = 1;
    const lifecycleFetch = async (url) => {
      const s = String(url);
      if (s.includes('api.github.com/advisories') && s.includes('cve_id=')) {
        return { ok: true, status: 200, json: async () => [] };
      }
      if (s.includes('api.github.com/advisories')) {
        if (phase === 1) {
          return {
            ok: true,
            status: 200,
            json: async () => ([
              {
                ghsa_id: 'GHSA-1111-2222-3333',
                cve_id: 'CVE-2026-11111',
                severity: 'medium',
                summary: 'Inclusive bound package issue',
                references: ['https://github.com/acme/pkg/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                cwes: [{ cwe_id: 'CWE-20' }],
                vulnerabilities: [
                  {
                    package: { ecosystem: 'npm', name: 'inc-pkg' },
                    vulnerable_version_range: '>= 1.0.0, <= 1.2.4'
                  }
                ]
              }
            ])
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ([
            {
              ghsa_id: 'GHSA-2222-3333-4444',
              cve_id: 'CVE-2026-22222',
              severity: 'high',
              summary: 'Second sync package issue',
              references: ['https://github.com/acme/other/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
              cwes: [{ cwe_id: 'CWE-79' }],
              vulnerabilities: [
                {
                  package: { ecosystem: 'npm', name: 'other-pkg' },
                  vulnerable_version_range: '< 2.0.0',
                  first_patched_version: { identifier: '2.0.0' }
                }
              ]
            }
          ])
        };
      }
      if (s.includes('known_exploited_vulnerabilities.json')) {
        if (phase === 1) {
          return { ok: true, status: 200, json: async () => ({ vulnerabilities: [] }) };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            vulnerabilities: [
              { cveID: 'CVE-2026-11111', dateAdded: '2026-11-14', vulnerabilityName: 'Existing KEV Upgrade' },
              { cveID: 'CVE-2026-99999', dateAdded: '2026-11-15', vulnerabilityName: 'OSV Fallback KEV' }
            ]
          })
        };
      }
      if (s.includes('api.osv.dev/v1/vulns/CVE-2026-99999')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            id: 'GO-2026-9999',
            aliases: ['CVE-2026-99999'],
            summary: 'Go OSV fallback vulnerability',
            database_specific: { severity: 'CRITICAL', cwe_ids: ['CWE-94'] },
            affected: [
              {
                package: { ecosystem: 'Go', name: 'github.com/example/vulnerable' },
                ranges: [
                  {
                    type: 'SEMVER',
                    events: [{ introduced: '0.1.0' }, { last_affected: '0.2.9' }]
                  }
                ]
              }
            ]
          })
        };
      }
      if (s.includes('api.first.org/data/v1/epss')) {
        if (phase === 1) {
          return { ok: true, status: 200, json: async () => ({ data: [] }) };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: [
              { cve: 'CVE-2026-11111', epss: '0.9123', percentile: '0.99' },
              { cve: 'CVE-2026-99999', epss: '0.7500', percentile: '0.95' }
            ]
          })
        };
      }
      throw new Error(`Unexpected lifecycle URL: ${s}`);
    };

    const lc1 = await mod.syncAdvisoriesFromInternet({
      outFile: advOut2,
      rawOutFile: rawOut2,
      kevLookupLimit: 0,
      fetchImpl: lifecycleFetch
    });
    assert.equal(lc1.db.npm.length, 1);
    assert.equal(lc1.db.npm[0].le, '1.2.4');
    assert.equal(lc1.db.npm[0].lt, undefined);
    assert.equal(lc1.db.npm[0].sev, 'medium');

    phase = 2;
    const lc2 = await mod.syncAdvisoriesFromInternet({
      outFile: advOut2,
      rawOutFile: rawOut2,
      kevLookupLimit: 1,
      backfillEpss: true,
      fetchImpl: lifecycleFetch
    });
    assert.equal(lc2.changed, true);
    assert.ok(lc2.updated >= 1, 'Stored advisory must record KEV/EPSS/sev upgrades');
    const upgradedIncPkg = lc2.db.npm.find((p) => p.name === 'inc-pkg');
    assert.ok(upgradedIncPkg);
    assert.equal(upgradedIncPkg.kev, true);
    assert.equal(upgradedIncPkg.sev, 'high');
    assert.equal(upgradedIncPkg.epss, 0.9123);
    const patchedObjPkg = lc2.db.npm.find((p) => p.name === 'other-pkg');
    assert.equal(patchedObjPkg.lt, '2.0.0');
    assert.equal(lc2.db.go.length, 1);
    assert.equal(lc2.db.go[0].name, 'github.com/example/vulnerable');
    assert.equal(lc2.db.go[0].ge, '0.1.0');
    assert.equal(lc2.db.go[0].le, '0.2.9');
    assert.equal(lc2.db.go[0].kev, true);
    assert.ok(lc2.sources.includes('osv-dev'));
    const rawDoc2 = JSON.parse(fs.readFileSync(rawOut2, 'utf8'));
    assert.equal(rawDoc2.count, 3, 'raw-advisories.json must retain cumulative advisories across sync runs');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  const pruneSource = {
    version: 1,
    generatedAt: '2026-11-16T00:00:00.000Z',
    sources: [],
    stats: { total: 6, kevCount: 1, highEpssCount: 0, byEcosystem: { npm: 6 } },
    npm: [
      { name: 'low-1', lt: '1.0.0', id: 'GHSA-1', cwe: 'CWE-20', sev: 'low', note: 'n' },
      { name: 'low-2', lt: '1.0.0', id: 'GHSA-2', cwe: 'CWE-20', sev: 'low', note: 'n' },
      { name: 'med-1', lt: '1.0.0', id: 'GHSA-3', cwe: 'CWE-20', sev: 'medium', note: 'n' },
      { name: 'med-2', lt: '1.0.0', id: 'GHSA-4', cwe: 'CWE-20', sev: 'medium', note: 'n' },
      { name: 'crit-1', lt: '1.0.0', id: 'GHSA-5', cwe: 'CWE-94', sev: 'critical', note: 'n' },
      { name: 'kev-1', lt: '1.0.0', id: 'CVE-2026-0001', cve: 'CVE-2026-0001', cwe: 'CWE-287', sev: 'high', kev: true, note: 'n' }
    ],
    pip: [],
    maven: [],
    go: [],
    cargo: [],
    nuget: [],
    composer: [],
    rubygems: []
  };
  const prunedRes = mod.pruneAdvisoryDb(pruneSource, { maxPerEcosystem: 3, maxTotal: 3 });
  assert.equal(prunedRes.prunedCount, 3);
  assert.equal(prunedRes.db.stats.total, 3);
  assert.ok(prunedRes.db.npm.some((x) => x.kev === true));
  assert.ok(prunedRes.db.npm.some((x) => x.sev === 'critical'));

  const cleanDir = path.join(rootDir, 'tests', 'corpus', 'clean');
  const multiLangCorpus = mod.collectCleanCorpus([cleanDir]);
  for (const lang of ['js', 'ts', 'py', 'go', 'java', 'php', 'yaml']) {
    assert.ok(multiLangCorpus.some((s) => s.lang === lang), `Expected clean corpus samples for ${lang}`);
  }
  const noisyGoCandidate = {
    id: 'wide/noisy-go-test',
    name: 'noisy-go-test',
    category: 'INJECTION',
    severity: 'HIGH',
    languages: ['go'],
    pattern: 'QueryRowContext',
    message: 'Test noisy Go rule',
    tests: { positive: ['db.QueryRowContext(ctx, q)'], negative: ['ok()'] }
  };
  assert.equal(mod.verifyRuleCandidate(noisyGoCandidate, { corpus: multiLangCorpus, maxFalsePositives: 0 }).ok, false);

  assert.equal(
    mod.selectLearningCandidates({
      advisories: [{ id: 'GHSA-no-patch', sev: 'critical', kev: true, patchUrls: [] }]
    }).length,
    0,
    'Advisories without patchUrls must be excluded from rule synthesis'
  );

  const skippedJsonSynth = await mod.synthesizeRuleFromAdvisory({
    advisory: { id: 'GHSA-json-only', sev: 'high', summary: 'Version check' },
    patchDiff: '',
    provider: 'custom',
    completeFn: async () => ({
      category: 'GENERAL',
      severity: 'HIGH',
      languages: ['json'],
      pattern: '"bad-pkg":',
      message: 'Manifest rule',
      tests: { positive: ['"bad-pkg": "1.0.0"'], negative: ['"bad-pkg": "2.0.0"'] }
    })
  });
  assert.equal(skippedJsonSynth.skipped, true);

  const multilineVuln = [
    'const userId = req.query.id;',
    'const safeId = parseInt(req.query.page, 10);',
    'pool.query(',
    '  "SELECT * FROM orders WHERE user = " +',
    '  userId',
    ');',
    'pool.query("SELECT * FROM orders WHERE page = $1", [safeId]);'
  ].join('\n');
  const taintHits = mod.analyzeFileTaint(multilineVuln, 'js', 'orders.js');
  assert.equal(taintHits.length, 1);
  assert.equal(taintHits[0].cwe, 'CWE-89');
  assert.equal(taintHits[0].line, 3);

  const crossFlows = mod.analyzeProjectFlows([
    { file: 'sink.js', lang: 'js', content: 'export function runCmd(arg) { return exec("cat " + arg); }' },
    { file: 'routes.js', lang: 'js', content: 'const target = req.body.target;\nrunCmd(String(target));' }
  ]);
  const crossHit = crossFlows.find((f) => f.crossFile === true);
  assert.ok(crossHit, 'Cross-file taint flow must detect source passing into helper sink');
  assert.equal(crossHit.cwe, 'CWE-78');
  assert.equal(crossHit.file, 'routes.js');

  assert.equal(mod.isLikelyRealSecret('const apiKey = "EXAMPLE_YOUR_API_KEY_HERE";', 'app.js'), false);
  assert.equal(mod.isLikelyRealSecret('const apiKey = "aaaaaaaaaaaaaaaaaaaa";', 'app.js'), false);
  assert.equal(mod.isLikelyRealSecret('const gh = "ghp_9xK2mP7qR4tV8wZ1aB3cD5eF6gH8jL0nM2q";', 'app.js'), true);

  assert.equal(
    mod.verifyRuleCandidate(
      {
        id: 'wide/too-short-test',
        name: 'too-short-test',
        category: 'GENERAL',
        severity: 'MEDIUM',
        languages: ['js'],
        pattern: 'eval\\(',
        message: 'Short pattern test',
        tests: { positive: ['eval(x)'], negative: ['safe(x)'] }
      },
      { strictPrecision: true, corpus: multiLangCorpus }
    ).ok,
    false,
    'strictPrecision must reject overly short patterns before auto-merge'
  );

  const learnTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wide-learn-rev-'));
  try {
    const revOut = await mod.learnRulesFromAdvisories({
      advisories: [
        {
          id: 'CVE-2026-88881',
          cve: 'CVE-2026-88881',
          cwe: 'CWE-94',
          sev: 'critical',
          kev: true,
          patchUrls: ['https://github.com/org/repo/commit/abcdef1'],
          summary: 'Mock RCE'
        }
      ],
      existingRules: [],
      outDir: path.join(learnTmp, 'rules'),
      stateFile: path.join(learnTmp, 'state.json'),
      completeFn: async () => ({
        category: 'INJECTION',
        severity: 'CRITICAL',
        languages: ['js'],
        pattern: 'dangerousExecCall\\(\\s*req\\.body',
        'not-match': 'sanitizeInput',
        confidence: 'high',
        message: 'Unsanitized dangerousExecCall',
        tests: { positive: ['dangerousExecCall(req.body.cmd)'], negative: ['dangerousExecCall(sanitizeInput(x))'] }
      }),
      reviewFn: async () => ({ approved: false, falsePositiveRisk: 'high', reason: 'Overly broad in tests' })
    });
    assert.equal(revOut.learned.length, 0);
    assert.equal(revOut.rejected.length, 1);
    assert.ok(revOut.rejected[0].reason.includes('AI FP review rejected'));

    const badLangCheck = mod.verifyRuleCandidate({
      id: 'wide/unsupported-lang-test',
      name: 'unsupported-lang-test',
      category: 'INJECTION',
      severity: 'HIGH',
      languages: ['vtl'],
      pattern: 'response\\.writer\\.print\\(',
      message: 'Unsupported lang',
      tests: { positive: ['response.writer.print(x)'], negative: ['safe(x)'] }
    });
    assert.equal(badLangCheck.ok, false);
    assert.ok(badLangCheck.errors.some((e) => e.includes('Unsupported language')));

    const promoDir = path.join(learnTmp, 'promo');
    fs.mkdirSync(promoDir, { recursive: true });
    const yaml = require('js-yaml');
    fs.writeFileSync(
      path.join(promoDir, 'exp-rule.yml'),
      yaml.dump({
        id: 'wide/exp-rule-test',
        name: 'exp-rule-test',
        category: 'INJECTION',
        severity: 'HIGH',
        languages: ['js'],
        pattern: 'dangerousSinkExec\\(\\s*req\\.query',
        'not-match': 'sanitizeSink',
        confidence: 'medium',
        message: 'Experimental rule test',
        metadata: {
          source: 'wide-rules-auto-learn',
          status: 'experimental',
          quarantineUntil: '2026-01-01T00:00:00.000Z'
        },
        tests: {
          positive: ['dangerousSinkExec(req.query.cmd)'],
          negative: ['dangerousSinkExec(sanitizeSink(x))']
        }
      }),
      'utf8'
    );
    const promotedIds = mod.promoteMaturedRules(promoDir, { corpus: multiLangCorpus });
    assert.deepEqual(promotedIds, ['wide/exp-rule-test']);
    const promotedDoc = yaml.load(fs.readFileSync(path.join(promoDir, 'exp-rule.yml'), 'utf8'));
    assert.equal(promotedDoc.metadata.status, 'verified');
  } finally {
    fs.rmSync(learnTmp, { recursive: true, force: true });
  }

  console.log('All rule engine and dynamic learning tests passed successfully.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
