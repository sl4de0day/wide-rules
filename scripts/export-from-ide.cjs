const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const ideRulesPath = 'C:/Users/yusuf/Downloads/wide/wide/apps/renderer/src/editor/features/inspect/rules.ts';
const rulesRepoRoot = path.resolve(__dirname, '..');

let code = fs.readFileSync(ideRulesPath, 'utf8');
code = code.replace(/export type Severity = [^;]+;/g, '');
code = code.replace(/export interface Rule \{[\s\S]*?\}/g, '');
code = code.replace(/export const BUILT_IN_RULES: Rule\[\] =/g, 'const BUILT_IN_RULES =');

const tempPath = path.join(__dirname, 'temp_ide_rules.cjs');
fs.writeFileSync(tempPath, code + '\nmodule.exports = { BUILT_IN_RULES };', 'utf8');

const { BUILT_IN_RULES } = require(tempPath);
fs.unlinkSync(tempPath);

function determineCategory(r) {
  const cwe = (r.cwe || '').toUpperCase();
  const id = r.id.toLowerCase();

  if (cwe === 'CWE-89' || cwe === 'CWE-78' || cwe === 'CWE-94' || cwe === 'CWE-95' || cwe === 'CWE-88' || cwe === 'CWE-113' || cwe === 'CWE-1336' || cwe === 'CWE-943' || id.includes('inject') || id.includes('sqli') || id.includes('arginj')) {
    return 'injection';
  }
  if (cwe === 'CWE-79' || id.includes('xss')) {
    return 'xss';
  }
  if (cwe === 'CWE-798' || cwe === 'CWE-259' || cwe === 'CWE-312' || id.includes('secret') || id.includes('token') || id.includes('key') || id.includes('cred') || id.includes('password')) {
    return 'secrets';
  }
  if (cwe === 'CWE-327' || cwe === 'CWE-328' || cwe === 'CWE-330' || cwe === 'CWE-326' || cwe === 'CWE-916' || cwe === 'CWE-347' || id.includes('crypto') || id.includes('hash') || id.includes('cipher')) {
    return 'crypto';
  }
  if (cwe === 'CWE-918' || cwe === 'CWE-601' || cwe === 'CWE-942' || cwe === 'CWE-352' || cwe === 'CWE-829' || cwe === 'CWE-290' || id.includes('ssrf') || id.includes('redirect') || id.includes('cors') || id.includes('csrf')) {
    return 'network';
  }
  if (cwe === 'CWE-22' || cwe === 'CWE-73' || cwe === 'CWE-434' || id.includes('traversal') || id.includes('upload') || id.includes('file')) {
    return 'filesystem';
  }
  if (cwe === 'CWE-502' || cwe === 'CWE-611' || cwe === 'CWE-134' || id.includes('deserial') || id.includes('xxe') || id.includes('format')) {
    return 'deserialization';
  }
  if (cwe === 'CWE-1321' || cwe === 'CWE-915' || id.includes('proto') || id.includes('pollut')) {
    return 'prototype';
  }
  if (cwe === 'CWE-287' || cwe === 'CWE-384' || cwe === 'CWE-639' || cwe === 'CWE-602' || cwe === 'CWE-807' || cwe === 'CWE-235' || id.includes('auth') || id.includes('idor') || id.includes('session') || id.includes('privilege')) {
    return 'auth';
  }
  if (cwe === 'CWE-1284' || cwe === 'CWE-190' || cwe === 'CWE-682' || id.includes('overflow') || id.includes('numeric') || id.includes('isnan')) {
    return 'logic';
  }
  return 'general';
}

function determineSeverity(r) {
  const cwe = (r.cwe || '').toUpperCase();
  if (['CWE-89', 'CWE-78', 'CWE-94', 'CWE-502', 'CWE-943', 'CWE-798'].includes(cwe)) {
    return 'CRITICAL';
  }
  if (r.severity === 'error') return 'HIGH';
  if (r.severity === 'warning') return 'MEDIUM';
  if (r.severity === 'info') return 'LOW';
  return 'MEDIUM';
}

let exportedCount = 0;
const categoryDirs = new Set();

for (const rule of BUILT_IN_RULES) {
  const category = determineCategory(rule);
  const severity = determineSeverity(rule);
  const rawId = rule.id.startsWith('wide/') ? rule.id.slice(5) : rule.id;
  const ruleName = rawId.replace(/\//g, '-').toLowerCase();
  const ruleId = `wide/${ruleName}`;
  const dir = path.join(rulesRepoRoot, 'rules', category);

  categoryDirs.add(dir);
  fs.mkdirSync(dir, { recursive: true });

  const patternRegex = rule.text || rule.match;
  const patternStr = patternRegex ? patternRegex.source : '';

  const doc = {
    id: ruleId,
    name: ruleName,
    category: category.toUpperCase(),
    severity,
    languages: rule.languages || ['all'],
    cwe: rule.cwe || 'N/A',
    pattern: patternStr,
    message: rule.message || '',
    remediation: rule.fix || rule.why || 'Review and sanitize unescaped inputs.'
  };

  if (rule.notMatch) {
    doc['not-match'] = rule.notMatch.source;
  }
  if (rule.why) {
    doc.why = rule.why;
  }
  if (rule.confidence) {
    doc.confidence = rule.confidence;
  }

  const outFilePath = path.join(dir, `${ruleName}.yml`);
  fs.writeFileSync(outFilePath, yaml.dump(doc, { indent: 2, lineWidth: -1 }), 'utf8');
  exportedCount++;
}

console.log(`Successfully exported ${exportedCount} rules across ${categoryDirs.size} categories.`);
