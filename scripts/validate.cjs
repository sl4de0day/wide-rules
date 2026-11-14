const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const yaml = require('js-yaml');

const rootDir = path.resolve(__dirname, '..');
const rulesDir = path.join(rootDir, 'rules');

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

async function main() {
  const { checkRegexSafety } = await import(pathToFileURL(path.join(rootDir, 'src', 'learning', 'redos.js')).href);
  const { verifyRuleCandidate } = await import(pathToFileURL(path.join(rootDir, 'src', 'learning', 'verifier.js')).href);

  const yamlFiles = getAllYamlFiles(rulesDir);
  console.log(`Validating ${yamlFiles.length} rule files...`);

  const ids = new Set();
  let errorCount = 0;

  for (const file of yamlFiles) {
    const rel = path.relative(rootDir, file);
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const doc = yaml.load(raw);

      if (!doc || typeof doc !== 'object') {
        console.error(`ERROR in ${rel}: Empty or invalid YAML content.`);
        errorCount++;
        continue;
      }

      if (!doc.id || typeof doc.id !== 'string') {
        console.error(`ERROR in ${rel}: Missing or invalid 'id' field.`);
        errorCount++;
      } else if (ids.has(doc.id)) {
        console.error(`ERROR in ${rel}: Duplicate rule id '${doc.id}'.`);
        errorCount++;
      } else {
        ids.add(doc.id);
      }

      if (!doc.name || typeof doc.name !== 'string') {
        console.error(`ERROR in ${rel}: Missing or invalid 'name' field.`);
        errorCount++;
      }

      if (!doc.severity || !['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(doc.severity)) {
        console.error(`ERROR in ${rel}: Invalid 'severity' value '${doc.severity}'.`);
        errorCount++;
      }

      if (!Array.isArray(doc.languages) || doc.languages.length === 0) {
        console.error(`ERROR in ${rel}: 'languages' must be a non-empty array.`);
        errorCount++;
      }

      if (!doc.pattern || typeof doc.pattern !== 'string') {
        console.error(`ERROR in ${rel}: Missing or invalid 'pattern' field.`);
        errorCount++;
      } else {
        const res = checkRegexSafety(doc.pattern, { strictStatic: false, maxProbeMs: 25 });
        if (!res.safe) {
          console.error(`ERROR in ${rel}: pattern check failed: ${res.reason}`);
          errorCount++;
        }
      }

      if (doc['not-match']) {
        const nmRes = checkRegexSafety(doc['not-match'], { strictStatic: false, maxProbeMs: 25 });
        if (!nmRes.safe) {
          console.error(`ERROR in ${rel}: not-match check failed: ${nmRes.reason}`);
          errorCount++;
        }
      }

      if (doc.tests && typeof doc.tests === 'object') {
        const check = verifyRuleCandidate(doc, { requireTests: false, maxFalsePositives: 999 });
        if (!check.ok) {
          for (const msg of check.errors) {
            console.error(`ERROR in ${rel}: ${msg}`);
            errorCount++;
          }
        }
      }
    } catch (err) {
      console.error(`ERROR reading ${rel}: ${err.message}`);
      errorCount++;
    }
  }

  if (errorCount > 0) {
    console.error(`Validation failed with ${errorCount} error(s).`);
    process.exit(1);
  } else {
    console.log(`Validation SUCCESS: ${yamlFiles.length} rules are 100% valid!`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
