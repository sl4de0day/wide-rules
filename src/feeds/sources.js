import * as fs from "node:fs";
import * as path from "node:path";

export const GHSA_API_URL = "https://api.github.com/advisories";
export const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const FIRST_EPSS_URL = "https://api.first.org/data/v1/epss";
export const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";
export const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";

const ECO_MAP = {
  npm: "npm",
  pip: "pip",
  pypi: "pip",
  maven: "maven",
  go: "go",
  cargo: "cargo",
  crates: "cargo",
  "crates.io": "cargo",
  nuget: "nuget",
  composer: "composer",
  packagist: "composer",
  rubygems: "rubygems"
};

const PATCH_URL_RE = /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+\/(?:commit|pull)\/[^\s#]+/i;

export function normalizeEcosystem(raw) {
  if (!raw || typeof raw !== "string") return null;
  return ECO_MAP[raw.trim().toLowerCase()] || null;
}

export async function fetchJson(url, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("Global fetch is not available in this Node.js runtime.");
  }
  const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 20000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchImpl(url, {
      method: options.method || "GET",
      headers: {
        "User-Agent": "Wide-Rules-Sync/1.0",
        Accept: "application/json",
        ...(options.headers || {})
      },
      body: options.body ? (typeof options.body === "string" ? options.body : JSON.stringify(options.body)) : undefined,
      signal: controller.signal
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${url}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchText(url, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("Global fetch is not available in this Node.js runtime.");
  }
  const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 20000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchImpl(url, {
      method: options.method || "GET",
      headers: {
        "User-Agent": "Wide-Rules-Sync/1.0",
        ...(options.headers || {})
      },
      signal: controller.signal
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${url}`);
    }
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

function parseVersionRangeBounds(rawRange) {
  if (!rawRange || typeof rawRange !== "string") return {};
  const parts = rawRange.split(",").map((s) => s.trim()).filter(Boolean);
  let ge;
  let lt;

  for (const part of parts) {
    if (part.startsWith(">=")) {
      ge = part.slice(2).trim();
    } else if (part.startsWith(">")) {
      ge = part.slice(1).trim();
    } else if (part.startsWith("<=")) {
      lt = part.slice(2).trim();
    } else if (part.startsWith("<")) {
      lt = part.slice(1).trim();
    }
  }
  return { ge, lt };
}

export function normalizeGhsaAdvisory(raw) {
  if (!raw || typeof raw !== "object") return null;
  const cveId = typeof raw.cve_id === "string" && raw.cve_id ? raw.cve_id : null;
  const ghsaId = typeof raw.ghsa_id === "string" && raw.ghsa_id ? raw.ghsa_id : null;
  const id = cveId || ghsaId;
  if (!id) return null;

  const refs = Array.isArray(raw.references)
    ? raw.references.filter((r) => typeof r === "string")
    : [];
  const patchUrls = refs.filter((u) => PATCH_URL_RE.test(u));

  const cweIds = Array.isArray(raw.cwes)
    ? raw.cwes.map((c) => c && c.cwe_id).filter(Boolean)
    : [];
  const cwe = cweIds[0] || "CWE-1395";
  const sevRaw = String(raw.severity || "medium").toLowerCase();
  const sev = ["critical", "high", "medium", "low"].includes(sevRaw) ? sevRaw : "medium";
  const note = String(raw.summary || raw.description || "listed in GitHub Advisory Database")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 220);

  const packages = [];
  for (const v of Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : []) {
    const eco = normalizeEcosystem(v?.package?.ecosystem);
    const name = v?.package?.name;
    if (!eco || !name) continue;
    const range = parseVersionRangeBounds(v.vulnerable_version_range);
    const fixed = v.first_patched_version || range.lt;
    if (!fixed) continue;
    packages.push({
      ecosystem: eco,
      name: String(name),
      ge: range.ge || undefined,
      lt: String(fixed),
      id,
      ghsaId: ghsaId || undefined,
      cve: cveId || undefined,
      cwe,
      sev,
      note
    });
  }

  return {
    id,
    ghsaId,
    cve: cveId,
    cwe,
    sev,
    summary: note,
    description: String(raw.description || "").slice(0, 2500),
    publishedAt: raw.published_at || null,
    updatedAt: raw.updated_at || null,
    url: raw.html_url || null,
    references: refs.slice(0, 12),
    patchUrls: patchUrls.slice(0, 6),
    packages
  };
}

export async function fetchGitHubAdvisories(options = {}) {
  const perPage = Math.min(Math.max(Number(options.perPage || 100), 1), 100);
  const pages = Math.min(Math.max(Number(options.pages || 2), 1), 10);
  const token = options.token || process.env.GITHUB_TOKEN || "";
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const advisories = [];
  for (let page = 1; page <= pages; page++) {
    const params = new URLSearchParams({
      type: options.type || "reviewed",
      per_page: String(perPage),
      page: String(page),
      sort: "updated",
      direction: "desc"
    });
    if (options.ecosystem) params.set("ecosystem", options.ecosystem);
    if (options.severity) params.set("severity", options.severity);
    if (options.updated) params.set("updated", options.updated);

    const list = await fetchJson(`${GHSA_API_URL}?${params.toString()}`, {
      headers,
      fetchImpl: options.fetchImpl,
      timeoutMs: options.timeoutMs
    });

    if (!Array.isArray(list) || list.length === 0) break;
    for (const raw of list) {
      const normalized = normalizeGhsaAdvisory(raw);
      if (normalized) advisories.push(normalized);
    }
    if (list.length < perPage) break;
  }

  return advisories;
}

export async function fetchCisaKev(options = {}) {
  const data = await fetchJson(options.url || CISA_KEV_URL, {
    fetchImpl: options.fetchImpl,
    timeoutMs: options.timeoutMs
  });
  const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  const byCve = new Map();

  for (const item of list) {
    const cve = String(item?.cveID || "").trim().toUpperCase();
    if (!cve) continue;
    byCve.set(cve, {
      cve,
      vendor: item.vendorProject || "",
      product: item.product || "",
      name: item.vulnerabilityName || "",
      dateAdded: item.dateAdded || "",
      shortDescription: item.shortDescription || "",
      knownRansomwareCampaignUse: item.knownRansomwareCampaignUse || "Unknown"
    });
  }

  return {
    catalogVersion: data?.catalogVersion || null,
    count: byCve.size,
    byCve,
    list
  };
}

export async function fetchEpssScores(cveIds, options = {}) {
  const unique = [...new Set(
    (Array.isArray(cveIds) ? cveIds : [])
      .map((c) => String(c || "").trim().toUpperCase())
      .filter((c) => /^CVE-\d{4}-\d+$/.test(c))
  )];

  const scores = new Map();
  if (unique.length === 0) return scores;

  const chunkSize = 80;
  for (let i = 0; i < unique.length; i += chunkSize) {
    const chunk = unique.slice(i, i + chunkSize);
    const url = `${options.url || FIRST_EPSS_URL}?cve=${encodeURIComponent(chunk.join(","))}`;
    const res = await fetchJson(url, {
      fetchImpl: options.fetchImpl,
      timeoutMs: options.timeoutMs
    });
    for (const row of Array.isArray(res?.data) ? res.data : []) {
      const cve = String(row?.cve || "").trim().toUpperCase();
      if (!cve) continue;
      scores.set(cve, {
        epss: Number(row.epss || 0),
        percentile: Number(row.percentile || 0),
        date: row.date || null
      });
    }
  }

  return scores;
}

export async function fetchOsvVuln(vulnId, options = {}) {
  const cleanId = encodeURIComponent(String(vulnId || "").trim());
  return fetchJson(`${OSV_VULN_URL}/${cleanId}`, {
    fetchImpl: options.fetchImpl,
    timeoutMs: options.timeoutMs
  });
}

export async function queryOsvBatch(queries, options = {}) {
  if (!Array.isArray(queries) || queries.length === 0) return [];
  const results = [];
  const batchSize = 500;

  for (let i = 0; i < queries.length; i += batchSize) {
    const slice = queries.slice(i, i + batchSize);
    const res = await fetchJson(options.url || OSV_QUERYBATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { queries: slice },
      fetchImpl: options.fetchImpl,
      timeoutMs: options.timeoutMs
    });
    const batchResults = Array.isArray(res?.results) ? res.results : [];
    for (let j = 0; j < slice.length; j++) {
      results.push({
        query: slice[j],
        vulns: Array.isArray(batchResults[j]?.vulns) ? batchResults[j].vulns : []
      });
    }
  }

  return results;
}

export function extractManifestQueries(targetPath) {
  const resolved = path.resolve(targetPath || ".");
  const files = [];

  if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
    files.push(resolved);
  } else if (fs.existsSync(resolved)) {
    for (const name of ["package.json", "package-lock.json", "requirements.txt", "go.mod"]) {
      const candidate = path.join(resolved, name);
      if (fs.existsSync(candidate)) files.push(candidate);
    }
  }

  const queries = [];
  const seen = new Set();
  const add = (ecosystem, name, version) => {
    const cleanVer = String(version || "").replace(/^[~^>=<\s]+/, "").split(/\s+/)[0];
    if (!name || !cleanVer || /^\*|latest|workspace:/i.test(cleanVer)) return;
    const key = `${ecosystem}:${name}@${cleanVer}`;
    if (seen.has(key)) return;
    seen.add(key);
    queries.push({ package: { ecosystem, name }, version: cleanVer });
  };

  for (const file of files) {
    const base = path.basename(file).toLowerCase();
    const content = fs.readFileSync(file, "utf8");
    if (base === "package.json") {
      try {
        const pkg = JSON.parse(content);
        const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies);
        for (const [name, ver] of Object.entries(deps)) add("npm", name, ver);
      } catch {}
    } else if (base === "package-lock.json") {
      try {
        const lock = JSON.parse(content);
        if (lock.packages && typeof lock.packages === "object") {
          for (const [p, info] of Object.entries(lock.packages)) {
            const pkgName = p.split("node_modules/").pop();
            if (pkgName && info?.version) add("npm", pkgName, info.version);
          }
        }
      } catch {}
    } else if (base === "requirements.txt") {
      for (const line of content.split(/\r?\n/)) {
        const m = /^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|<=)\s*([0-9][0-9A-Za-z.\-]*)/.exec(line);
        if (m) add("PyPI", m[1], m[2]);
      }
    } else if (base === "go.mod") {
      const re = /^\s*(?:require\s+)?([A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)\s+(v[0-9][0-9A-Za-z.\-+]*)/gm;
      let m;
      while ((m = re.exec(content))) add("Go", m[1], m[2]);
    }
  }

  return queries;
}
