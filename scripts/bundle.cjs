const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const yaml = require('js-yaml');

const rootDir = path.resolve(__dirname, '..');
const rulesDir = path.join(rootDir, 'rules');
const distDir = path.join(rootDir, 'dist');

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

const fullSha = crypto.createHash('sha256').update(fs.readFileSync(fullJsonPath)).digest('hex');
const minSha = crypto.createHash('sha256').update(fs.readFileSync(minJsonPath)).digest('hex');

const shaContent = `${fullSha}  rules.json\n${minSha}  rules.min.json\n`;
fs.writeFileSync(path.join(distDir, 'SHA256SUMS'), shaContent, 'utf8');

console.log(`Bundled ${rules.length} rules successfully into dist/rules.json (${(fs.statSync(fullJsonPath).size / 1024).toFixed(1)} KB) and dist/rules.min.json (${(fs.statSync(minJsonPath).size / 1024).toFixed(1)} KB).`);
