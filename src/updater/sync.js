import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  fetchCisaKev,
  fetchEpssScores,
  fetchGitHubAdvisories,
  fetchGitHubAdvisoryByCve,
  fetchJson,
  fetchText,
  normalizeEcosystem
} from "../feeds/sources.js";

const CURRENT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(CURRENT_DIR, "../..");

export const DEFAULT_CACHE_DIR = path.join(os.homedir(), ".wide", "rules");
export const REMOTE_BASE_URL = "https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist";

const ECOSYSTEMS = ["npm", "pip", "maven", "go", "cargo", "nuget", "composer", "rubygems"];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export function writeFileAtomicSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = path.join(dir, `.${path.basename(targetPath)}.tmp.${process.pid}.${Date.now()}`);
  fs.writeFileSync(tmpPath, content, "utf8");
  fs.renameSync(tmpPath, targetPath);
}

export function computeSha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

export function parseSha256Sums(text) {
  const map = new Map();
  if (!text || typeof text !== "string") return map;
  for (const line of text.split(/\r?\n/)) {
    const m = /^([a-fA-F0-9]{64})\s+\*?(.+)$/.exec(line.trim());
    if (m) {
      map.set(m[2].trim(), m[1].toLowerCase());
    }
  }
  return map;
}

export function createEmptyAdvisoriesDb() {
  const db = {
    version: 1,
    generatedAt: new Date().toISOString(),
    sources: [],
    stats: { total: 0, kevCount: 0, highEpssCount: 0, byEcosystem: {} }
  };
  for (const eco of ECOSYSTEMS) db[eco] = [];
  return db;
}

export function mergeAdvisoryRecords(existingDb, advisories, kevMap = new Map(), epssMap = new Map()) {
  const db = createEmptyAdvisoriesDb();
  const base = existingDb && typeof existingDb === "object" ? existingDb : {};
  const index = new Map();
  let added = 0;
  let updated = 0;

  const upsert = (eco, entry, isIncoming) => {
    const normEco = normalizeEcosystem(eco) || eco;
    if (!ECOSYSTEMS.includes(normEco)) return;
    if (!entry || !entry.name || !entry.lt) return;
    const cleanId = String(entry.id || entry.cve || entry.ghsaId || "advisory");
    const cveUpper = typeof entry.cve === "string"
      ? entry.cve.toUpperCase()
      : (/^CVE-\d{4}-\d+$/i.test(cleanId) ? cleanId.toUpperCase() : undefined);

    const kevInfo = cveUpper ? kevMap.get(cveUpper) : undefined;
    const epssInfo = cveUpper ? epssMap.get(cveUpper) : undefined;
    const baseSev = String(entry.sev || "medium").toLowerCase();
    const effectiveSev = kevInfo && SEV_RANK[baseSev] < SEV_RANK.high ? "high" : baseSev;

    const key = `${normEco}:${String(entry.name).toLowerCase()}:${cleanId.toLowerCase()}:${String(entry.lt)}`;
    const normalized = {
      name: String(entry.name),
      ...(entry.ge ? { ge: String(entry.ge) } : {}),
      lt: String(entry.lt),
      id: cleanId,
      ...(entry.ghsaId ? { ghsaId: String(entry.ghsaId) } : {}),
      ...(cveUpper ? { cve: cveUpper } : {}),
      cwe: String(entry.cwe || "CWE-1395"),
      sev: effectiveSev,
      note: String(entry.note || "listed in wide-rules advisory feed").slice(0, 220),
      ...(kevInfo || entry.kev ? { kev: true } : {}),
      ...(epssInfo ? { epss: Number(epssInfo.epss.toFixed(4)) } : (typeof entry.epss === "number" ? { epss: entry.epss } : {}))
    };

    const existing = index.get(key);
    if (!existing) {
      index.set(key, normalized);
      db[normEco].push(normalized);
      if (isIncoming) added++;
    } else if (isIncoming) {
      let changed = false;
      for (const field of ["ge", "cwe", "sev", "note", "kev", "epss", "ghsaId", "cve"]) {
        if (normalized[field] !== undefined && existing[field] !== normalized[field]) {
          existing[field] = normalized[field];
          changed = true;
        }
      }
      if (changed) updated++;
    }
  };

  for (const eco of ECOSYSTEMS) {
    if (Array.isArray(base[eco])) {
      for (const item of base[eco]) upsert(eco, item, false);
    }
  }

  for (const adv of Array.isArray(advisories) ? advisories : []) {
    for (const pkg of Array.isArray(adv.packages) ? adv.packages : []) {
      upsert(pkg.ecosystem, pkg, true);
    }
  }

  let total = 0;
  let kevCount = 0;
  let highEpssCount = 0;
  for (const eco of ECOSYSTEMS) {
    db[eco].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id) || a.lt.localeCompare(b.lt));
    db.stats.byEcosystem[eco] = db[eco].length;
    total += db[eco].length;
    for (const item of db[eco]) {
      if (item.kev) kevCount++;
      if (typeof item.epss === "number" && item.epss >= 0.3) highEpssCount++;
    }
  }

  db.stats.total = total;
  db.stats.kevCount = kevCount;
  db.stats.highEpssCount = highEpssCount;
  return { db, added, updated };
}

export async function syncAdvisoriesFromInternet(options = {}) {
  const outFile = options.outFile || path.join(REPO_ROOT, "data", "osv-advisories.json");
  const rawOutFile = options.rawOutFile || path.join(REPO_ROOT, "data", "raw-advisories.json");

  let existingDb = createEmptyAdvisoriesDb();
  let hadExistingDb = false;
  if (fs.existsSync(outFile)) {
    try {
      existingDb = JSON.parse(fs.readFileSync(outFile, "utf8"));
      hadExistingDb = true;
    } catch {}
  }

  const diversify = options.diversify !== false && !options.ecosystem && !options.fetchImpl;
  const ecosystemsToQuery = Array.isArray(options.ecosystems)
    ? options.ecosystems
    : diversify
      ? ["npm", "pip", "maven", "go", "rust"]
      : [];

  const sources = [];
  const advisories = await fetchGitHubAdvisories({
    perPage: options.perPage || 100,
    pages: options.pages || 2,
    ecosystem: options.ecosystem,
    ecosystems: ecosystemsToQuery,
    ecosystemPerPage: options.ecosystemPerPage || 30,
    severity: options.severity,
    updated: options.updated,
    token: options.token,
    fetchImpl: options.fetchImpl,
    timeoutMs: options.timeoutMs
  });
  sources.push("github-advisories");

  let kevResult = { byCve: new Map(), count: 0, list: [] };
  if (options.includeKev !== false) {
    try {
      kevResult = await fetchCisaKev({ fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs });
      sources.push("cisa-kev");
    } catch {}
  }

  const seenAdvIds = new Set(advisories.map((a) => String(a.id || "").toUpperCase()));
  const kevLimit = typeof options.kevLookupLimit === "number"
    ? options.kevLookupLimit
    : (options.fetchImpl ? 0 : 12);
  if (kevLimit > 0 && Array.isArray(kevResult.list) && kevResult.list.length > 0) {
    const existingCves = new Set();
    for (const eco of ECOSYSTEMS) {
      for (const item of Array.isArray(existingDb[eco]) ? existingDb[eco] : []) {
        if (item?.cve) existingCves.add(String(item.cve).toUpperCase());
      }
    }
    const recentKevs = [...kevResult.list]
      .filter((k) => k?.cveID && !seenAdvIds.has(String(k.cveID).toUpperCase()) && !existingCves.has(String(k.cveID).toUpperCase()))
      .sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")))
      .slice(0, kevLimit * 2);

    let fetchedKevCount = 0;
    for (const k of recentKevs) {
      if (fetchedKevCount >= kevLimit) break;
      try {
        const adv = await fetchGitHubAdvisoryByCve(k.cveID, {
          token: options.token,
          fetchImpl: options.fetchImpl,
          timeoutMs: options.timeoutMs
        });
        if (adv && Array.isArray(adv.packages) && adv.packages.length > 0 && !seenAdvIds.has(String(adv.id).toUpperCase())) {
          advisories.push(adv);
          seenAdvIds.add(String(adv.id).toUpperCase());
          fetchedKevCount++;
        }
      } catch {}
    }
  }

  let epssMap = new Map();
  if (options.includeEpss !== false) {
    try {
      const cves = advisories.map((a) => a.cve).filter(Boolean);
      epssMap = await fetchEpssScores(cves, { fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs });
      sources.push("first-epss");
    } catch {}
  }

  const enrichedAdvisories = advisories.map((adv) => {
    const cveUpper = adv.cve ? adv.cve.toUpperCase() : null;
    const kevInfo = cveUpper ? kevResult.byCve.get(cveUpper) : null;
    const epssInfo = cveUpper ? epssMap.get(cveUpper) : null;
    return {
      ...adv,
      kev: Boolean(kevInfo),
      epss: epssInfo ? epssInfo.epss : 0
    };
  });

  const { db, added, updated } = mergeAdvisoryRecords(existingDb, enrichedAdvisories, kevResult.byCve, epssMap);
  const prevSources = Array.isArray(existingDb.sources) ? existingDb.sources : [];
  db.sources = [...new Set([...prevSources, ...sources])];
  const sourcesChanged = db.sources.length !== prevSources.length || db.sources.some((s, i) => prevSources[i] !== s);
  const changed = !hadExistingDb || added > 0 || updated > 0 || sourcesChanged || Boolean(options.force);
  db.generatedAt = changed || !existingDb.generatedAt ? new Date().toISOString() : existingDb.generatedAt;

  if (!options.dryRun && changed) {
    writeFileAtomicSync(outFile, JSON.stringify(db, null, 2));
    writeFileAtomicSync(rawOutFile, JSON.stringify({ generatedAt: db.generatedAt, count: enrichedAdvisories.length, advisories: enrichedAdvisories }, null, 2));
  }

  return {
    outFile,
    rawOutFile,
    changed,
    fetchedAdvisories: enrichedAdvisories.length,
    kevMatched: enrichedAdvisories.filter((a) => a.kev).length,
    added,
    updated,
    total: db.stats.total,
    sources: db.sources,
    advisories: enrichedAdvisories,
    db
  };
}

export async function syncFromRemote(options = {}) {
  const cacheDir = options.cacheDir || DEFAULT_CACHE_DIR;
  const baseUrl = (options.baseUrl || REMOTE_BASE_URL).replace(/\/+$/, "");
  const rulesUrl = options.rulesUrl || `${baseUrl}/rules.json`;
  const osvUrl = options.osvUrl || `${baseUrl}/osv-bundle.json`;
  const checksumsUrl = options.checksumsUrl || `${baseUrl}/SHA256SUMS`;
  const verify = options.verifySha256 !== false;

  let checksums = new Map();
  if (verify) {
    let sumsText;
    try {
      sumsText = await fetchText(checksumsUrl, { fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs });
    } catch (err) {
      throw new Error(`Failed to fetch SHA256SUMS (${checksumsUrl}): ${String(err?.message || err)}`);
    }
    checksums = parseSha256Sums(sumsText);
    if (checksums.size === 0) {
      throw new Error(`SHA256SUMS from ${checksumsUrl} contains no valid checksums`);
    }
  }

  const rulesRaw = await fetchText(rulesUrl, { fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs });
  const expectedRulesHash = checksums.get("rules.json");
  if (verify) {
    if (!expectedRulesHash) {
      throw new Error("SHA256SUMS is missing required checksum entry for rules.json");
    }
    const actual = computeSha256(rulesRaw);
    if (actual !== expectedRulesHash) {
      throw new Error(`SHA-256 mismatch for rules.json (expected ${expectedRulesHash}, got ${actual})`);
    }
  }
  const rulesParsed = JSON.parse(rulesRaw);
  const rulesCount = Array.isArray(rulesParsed) ? rulesParsed.length : (Array.isArray(rulesParsed?.rules) ? rulesParsed.rules.length : 0);

  let osvCount = 0;
  let osvSynced = false;
  let osvSha256 = null;
  const expectedOsvHash = checksums.get("osv-bundle.json");
  try {
    const osvRaw = await fetchText(osvUrl, { fetchImpl: options.fetchImpl, timeoutMs: options.timeoutMs });
    if (verify && expectedOsvHash) {
      const actualOsv = computeSha256(osvRaw);
      if (actualOsv !== expectedOsvHash) {
        throw new Error(`SHA-256 mismatch for osv-bundle.json (expected ${expectedOsvHash}, got ${actualOsv})`);
      }
    } else if (verify && !expectedOsvHash) {
      throw new Error("SHA256SUMS is missing checksum entry for osv-bundle.json");
    }
    const osvParsed = JSON.parse(osvRaw);
    osvCount = typeof osvParsed?.stats?.total === "number"
      ? osvParsed.stats.total
      : ECOSYSTEMS.reduce((acc, eco) => acc + (Array.isArray(osvParsed?.[eco]) ? osvParsed[eco].length : 0), 0);
    writeFileAtomicSync(path.join(cacheDir, "osv-bundle.json"), JSON.stringify(osvParsed, null, 2));
    osvSha256 = computeSha256(osvRaw);
    osvSynced = true;
  } catch (err) {
    const msg = String(err?.message || "");
    if (msg.includes("SHA-256 mismatch") || msg.includes("SHA256SUMS") || (verify && expectedOsvHash)) {
      throw err;
    }
  }

  const rulesPath = path.join(cacheDir, "rules.json");
  writeFileAtomicSync(rulesPath, JSON.stringify(rulesParsed, null, 2));
  const rulesSha256 = computeSha256(rulesRaw);

  const meta = {
    syncedAt: new Date().toISOString(),
    rulesCount,
    rulesSha256,
    osvSynced,
    osvCount,
    osvSha256
  };
  writeFileAtomicSync(path.join(cacheDir, ".sync-meta.json"), JSON.stringify(meta, null, 2));

  return {
    cacheDir,
    rulesPath,
    rulesCount,
    osvPath: osvSynced ? path.join(cacheDir, "osv-bundle.json") : null,
    osvCount,
    verifiedSha256: verify && checksums.size > 0,
    syncedAt: meta.syncedAt
  };
}

export function loadAdvisories(options = {}) {
  const cacheDir = options.cacheDir || DEFAULT_CACHE_DIR;
  const candidates = [
    options.customPath ? path.resolve(options.customPath) : null,
    path.join(cacheDir, "osv-bundle.json"),
    path.join(REPO_ROOT, "dist", "osv-bundle.json"),
    path.join(REPO_ROOT, "data", "osv-advisories.json")
  ].filter(Boolean);

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
      } catch {}
    }
  }
  return createEmptyAdvisoriesDb();
}
