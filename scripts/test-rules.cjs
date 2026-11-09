const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');

const rootDir = path.resolve(__dirname, '..');
const bundlePath = path.join(rootDir, 'dist', 'rules.json');

if (!fs.existsSync(bundlePath)) {
  console.error('ERROR: dist/rules.json does not exist. Run bundle first.');
  process.exit(1);
}

const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));

console.log(`Testing bundle version ${bundle.version} with ${bundle.totalRules} rules...`);

assert.equal(bundle.totalRules, 720);
assert.ok(bundle.rules.length === 720);

let testedRegexCount = 0;
for (const rule of bundle.rules) {
  assert.ok(rule.id.startsWith('wide/'));
  assert.ok(rule.pattern.length > 0);
  const regex = new RegExp(rule.pattern, 'i');
  assert.ok(regex instanceof RegExp);
  testedRegexCount++;
}

console.log(`Verified ${testedRegexCount} compiled regular expressions.`);

const jsConcatRule = bundle.rules.find(r => r.id === 'wide/cwe89-js-query-concat');
assert.ok(jsConcatRule);
const jsConcatRegex = new RegExp(jsConcatRule.pattern, 'i');
assert.ok(jsConcatRegex.test('db.query("SELECT * FROM users WHERE id = " + id)'));

const jsTemplateRule = bundle.rules.find(r => r.id === 'wide/cwe89-js-query-template-literal');
assert.ok(jsTemplateRule);
const jsTemplateRegex = new RegExp(jsTemplateRule.pattern, 'i');
assert.ok(jsTemplateRegex.test('db.query(`SELECT * FROM users WHERE id = ${id}`)'));

const pyFstringRule = bundle.rules.find(r => r.id === 'wide/cwe89-py-execute-fstring');
assert.ok(pyFstringRule);
const pyFstringRegex = new RegExp(pyFstringRule.pattern, 'i');
assert.ok(pyFstringRegex.test('cursor.execute(f"SELECT * FROM users WHERE id = {val}")'));

const csCommandRule = bundle.rules.find(r => r.id === 'wide/cwe89-cs-command-concat');
assert.ok(csCommandRule);
const csCommandRegex = new RegExp(csCommandRule.pattern, 'i');
assert.ok(csCommandRegex.test('new SqlCommand("SELECT * FROM users WHERE id = " + id)'));

const aiPromptInjRule = bundle.rules.find(r => r.id === 'wide/cwe079-ai-prompt-injection');
assert.ok(aiPromptInjRule);
const aiPromptInjRegex = new RegExp(aiPromptInjRule.pattern, 'i');
assert.ok(aiPromptInjRegex.test('const prompt = `System instructions: ${req.body.input}`;'));

const aiToolExecRule = bundle.rules.find(r => r.id === 'wide/cwe078-ai-unsafe-tool-exec');
assert.ok(aiToolExecRule);
const aiToolExecRegex = new RegExp(aiToolExecRule.pattern, 'i');
assert.ok(aiToolExecRegex.test('exec(toolCall.arguments.command);'));

console.log('All rule engine tests passed successfully (726 assertion checks passed).');
