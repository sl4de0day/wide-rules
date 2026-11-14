const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const yaml = require('js-yaml');

const rootDir = path.resolve(__dirname, '..');
const rulesDir = path.join(rootDir, 'rules');
const distDir = path.join(rootDir, 'dist');
const dataAdvisoriesPath = path.join(rootDir, 'data', 'osv-advisories.json');

fs.mkdirSync(distDir, { recursive: true });

function getAllYamlFiles(dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...getAllYamlFiles(full));
    } else if (entry.name.endsWith('.yml') || entry.name.endsWith('.yaml')) {
      results.push(full);
    }
  }
  return results;
}

const files = getAllYamlFiles(rulesDir);
const rules = [];
const categories = {};
const severities = {};

for (const file of files) {
  const raw = fs.readFileSync(file, 'utf8');
  const doc = yaml.load(raw);
  rules.push(doc);

  categories[doc.category] = (categories[doc.category] || 0) + 1;
  severities[doc.severity] = (severities[doc.severity] || 0) + 1;
}

rules.sort((a, b) => a.id.localeCompare(b.id));

const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));

const bundleData = {
  version: pkg.version,
  generatedAt: new Date().toISOString(),
  totalRules: rules.length,
  categories,
  severities,
  rules
};

const fullJsonPath = path.join(distDir, 'rules.json');
const minJsonPath = path.join(distDir, 'rules.min.json');

fs.writeFileSync(fullJsonPath, JSON.stringify(bundleData, null, 2), 'utf8');
fs.writeFileSync(minJsonPath, JSON.stringify(bundleData), 'utf8');

const artifacts = [
  ['rules.json', fullJsonPath],
  ['rules.min.json', minJsonPath]
];

let osvCount = 0;
if (fs.existsSync(dataAdvisoriesPath)) {
  const osvDoc = JSON.parse(fs.readFileSync(dataAdvisoriesPath, 'utf8'));
  const osvFullPath = path.join(distDir, 'osv-bundle.json');
  const osvMinPath = path.join(distDir, 'osv-bundle.min.json');
  fs.writeFileSync(osvFullPath, JSON.stringify(osvDoc, null, 2), 'utf8');
  fs.writeFileSync(osvMinPath, JSON.stringify(osvDoc), 'utf8');
  osvCount = Number(osvDoc?.stats?.total || 0);
  artifacts.push(['osv-bundle.json', osvFullPath], ['osv-bundle.min.json', osvMinPath]);
}

const shaLines = artifacts.map(([name, filePath]) => {
  const hash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  return `${hash}  ${name}`;
});
fs.writeFileSync(path.join(distDir, 'SHA256SUMS'), `${shaLines.join('\n')}\n`, 'utf8');

console.log(`Bundled ${rules.length} rules and ${osvCount} advisories successfully into dist/.`);
