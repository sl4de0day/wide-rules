const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const yaml = require('js-yaml');

const rootDir = path.resolve(__dirname, '..');
const rulesDir = path.join(rootDir, 'rules');
const schemaPath = path.join(rootDir, 'schemas', 'rule.schema.json');

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

function validateAgainstSchema(doc, schema) {
  const errs = [];
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return ['Document must be a YAML object.'];
  }
  for (const reqField of schema.required || []) {
    if (doc[reqField] === undefined || doc[reqField] === null || doc[reqField] === '') {
      errs.push(`Missing required schema property '${reqField}'.`);
    }
  }
  const props = schema.properties || {};
  for (const [key, spec] of Object.entries(props)) {
    const val = doc[key];
    if (val === undefined || val === null) continue;
    if (spec.type === 'string') {
      if (typeof val !== 'string') {
        errs.push(`Property '${key}' must be a string.`);
        continue;
      }
      if (spec.pattern && !(new RegExp(spec.pattern).test(val))) {
        errs.push(`Property '${key}' ('${val}') failed schema pattern ${spec.pattern}.`);
      }
      if (Array.isArray(spec.enum) && !spec.enum.includes(val)) {
        errs.push(`Property '${key}' has invalid value '${val}'; expected one of [${spec.enum.join(', ')}].`);
      }
    } else if (spec.type === 'array') {
      if (!Array.isArray(val)) {
        errs.push(`Property '${key}' must be an array.`);
      } else if (spec.items?.type === 'string' && !val.every((x) => typeof x === 'string' && x.length > 0)) {
        errs.push(`Property '${key}' must contain non-empty strings.`);
      }
    } else if (spec.oneOf && key === 'cve') {
      const valid = typeof val === 'string' || (Array.isArray(val) && val.every((x) => typeof x === 'string'));
      if (!valid) errs.push(`Property 'cve' must be a string or array of strings.`);
    } else if (spec.type === 'object' && key === 'tests') {
      if (typeof val !== 'object' || Array.isArray(val)) {
        errs.push(`Property 'tests' must be an object.`);
      } else {
        for (const tKey of Object.keys(val)) {
          if (tKey !== 'positive' && tKey !== 'negative') {
            errs.push(`Unknown property 'tests.${tKey}'.`);
          } else if (!Array.isArray(val[tKey]) || !val[tKey].every((x) => typeof x === 'string')) {
            errs.push(`Property 'tests.${tKey}' must be an array of strings.`);
          }
        }
      }
    } else if (spec.type === 'object' && key === 'metadata') {
      if (typeof val !== 'object' || Array.isArray(val)) {
        errs.push(`Property 'metadata' must be an object.`);
      } else {
        if (val.kev !== undefined && typeof val.kev !== 'boolean') errs.push(`Property 'metadata.kev' must be boolean.`);
        if (val.epss !== undefined && typeof val.epss !== 'number') errs.push(`Property 'metadata.epss' must be number.`);
      }
    }
  }
  return errs;
}

async function main() {
  const { checkRegexSafety } = await import(pathToFileURL(path.join(rootDir, 'src', 'learning', 'redos.js')).href);
  const { verifyRuleCandidate } = await import(pathToFileURL(path.join(rootDir, 'src', 'learning', 'verifier.js')).href);

  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const yamlFiles = getAllYamlFiles(rulesDir);
  console.log(`Validating ${yamlFiles.length} rule files against ${path.basename(schemaPath)}...`);

  const ids = new Set();
  let errorCount = 0;

  for (const file of yamlFiles) {
    const rel = path.relative(rootDir, file);
    try {
      const raw = fs.readFileSync(file, 'utf8');
      if (/[\u200B-\u200D\uFEFF]/.test(raw)) {
        console.error(`ERROR in ${rel}: Contains literal invisible Unicode character; use escaped \\u200B/\\u200C/\\u200D.`);
        errorCount++;
      }
      const doc = yaml.load(raw);
      const schemaErrors = validateAgainstSchema(doc, schema);
      for (const msg of schemaErrors) {
        console.error(`ERROR in ${rel}: ${msg}`);
        errorCount++;
      }
      if (!doc || typeof doc !== 'object') continue;

      if (doc.id && typeof doc.id === 'string') {
        if (ids.has(doc.id)) {
          console.error(`ERROR in ${rel}: Duplicate rule id '${doc.id}'.`);
          errorCount++;
        } else {
          ids.add(doc.id);
        }
      }

      if (!Array.isArray(doc.languages) || doc.languages.length === 0) {
        console.error(`ERROR in ${rel}: 'languages' must be a non-empty array.`);
        errorCount++;
      }

      if (!doc.pattern || typeof doc.pattern !== 'string') {
        console.error(`ERROR in ${rel}: Missing or invalid 'pattern' field.`);
        errorCount++;
      } else {
        if (/[\u200B-\u200D\uFEFF]/.test(doc.pattern)) {
          console.error(`ERROR in ${rel}: pattern decodes to literal invisible Unicode character; single-quote '\\u200B' escapes.`);
          errorCount++;
        }
        const res = checkRegexSafety(doc.pattern, { strictStatic: true, maxProbeMs: 8 });
        if (!res.safe) {
          console.error(`ERROR in ${rel}: pattern check failed: ${res.reason}`);
          errorCount++;
        }
      }

      if (doc['not-match']) {
        const nmRes = checkRegexSafety(doc['not-match'], { strictStatic: true, maxProbeMs: 8 });
        if (!nmRes.safe) {
          console.error(`ERROR in ${rel}: not-match check failed: ${nmRes.reason}`);
          errorCount++;
        }
      }

      if (doc['source-pattern']) {
        const spRes = checkRegexSafety(doc['source-pattern'], { strictStatic: true, maxProbeMs: 8 });
        if (!spRes.safe) {
          console.error(`ERROR in ${rel}: source-pattern check failed: ${spRes.reason}`);
          errorCount++;
        }
      }

      if (doc.tests && typeof doc.tests === 'object') {
        const check = verifyRuleCandidate(doc, { strictStatic: true, maxProbeMs: 8, requireTests: false, maxFalsePositives: 0 });
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
