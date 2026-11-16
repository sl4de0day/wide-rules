#!/usr/bin/env node
import * as path from "node:path";
import { extractManifestQueries, fetchOsvVuln, queryOsvBatch } from "./feeds/sources.js";
import { learnRulesFromAdvisories } from "./learning/synthesizer.js";
import { loadAdvisories, syncAdvisoriesFromInternet, syncFromRemote } from "./updater/sync.js";

function parseArgs(argv) {
  const args = argv.slice(2);
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (!next || next.startsWith("--")) {
        flags[key] = true;
      } else {
        flags[key] = next;
        i++;
      }
    } else {
      positional.push(a);
    }
  }
  return { command: positional[0] || "help", rest: positional.slice(1), flags };
}

function printHelp() {
  console.log([
    "Wide Rules CLI",
    "",
    "Commands:",
    "  sync --remote              Download verified rules.json and osv-bundle.json into ~/.wide/rules",
    "  sync --feeds               Fetch latest advisories from GitHub Advisory, CISA KEV, FIRST EPSS",
    "    [--kev-limit N]          Maximum CISA KEV CVEs to lookup via GHSA/OSV (default 60)",
    "  learn [--limit N]          Synthesize and verify new CVE/GHSA rules into rules/learned/",
    "  query [dir-or-manifest]    Query live OSV API (api.osv.dev) for project dependencies",
    "  stats                      Show currently loaded advisory database counts"
  ].join("\n"));
}

async function main() {
  const { command, rest, flags } = parseArgs(process.argv);

  if (command === "help" || flags.help) {
    printHelp();
    return;
  }

  if (command === "sync") {
    if (flags.feeds) {
      const res = await syncAdvisoriesFromInternet({
        pages: Number(flags.pages || 2),
        perPage: Number(flags["per-page"] || 100),
        ecosystem: typeof flags.ecosystem === "string" ? flags.ecosystem : undefined,
        kevLookupLimit: flags["kev-limit"] !== undefined ? Number(flags["kev-limit"]) : undefined,
        dryRun: Boolean(flags["dry-run"])
      });
      console.log(`Synced advisories: total=${res.total}, added=${res.added}, updated=${res.updated}, kev=${res.kevMatched}, sources=${res.sources.join(",")}`);
      return;
    }

    const res = await syncFromRemote({
      verifySha256: flags["no-verify"] ? false : true
    });
    console.log(`Synced remote bundle -> ${res.cacheDir} (rules=${res.rulesCount}, osv=${res.osvCount}, sha256=${res.verifiedSha256})`);
    return;
  }

  if (command === "learn") {
    const res = await learnRulesFromAdvisories({
      limit: Number(flags.limit || 5),
      provider: typeof flags.provider === "string" ? flags.provider : undefined,
      model: typeof flags.model === "string" ? flags.model : undefined,
      dryRun: Boolean(flags["dry-run"])
    });
    if (!res.ok) {
      console.error(res.reason);
      process.exitCode = 1;
      return;
    }
    console.log(`Learn complete (${res.provider}): learned=${res.learned.length}, rejected=${res.rejected.length}`);
    for (const item of res.learned) {
      console.log(`  + ${item.ruleId} (${item.filePath})`);
    }
    for (const item of res.rejected) {
      console.log(`  - ${item.id}: ${item.reason}`);
    }
    return;
  }

  if (command === "query") {
    const target = rest[0] || ".";
    const queries = extractManifestQueries(target);
    if (queries.length === 0) {
      console.log(`No dependencies found under ${path.resolve(target)}`);
      return;
    }
    const hits = await queryOsvBatch(queries);
    let vulnTotal = 0;
    for (const row of hits) {
      if (!row.vulns.length) continue;
      for (const v of row.vulns) {
        vulnTotal++;
        let summary = "";
        try {
          const detail = await fetchOsvVuln(v.id);
          summary = detail?.summary || "";
        } catch {}
        console.log(`[${row.query.package.ecosystem}] ${row.query.package.name}@${row.query.version} -> ${v.id}${summary ? `: ${summary}` : ""}`);
      }
    }
    console.log(`Checked ${queries.length} dependencies; found ${vulnTotal} vulnerability hit(s).`);
    return;
  }

  if (command === "stats") {
    const repoPath = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "../data/osv-advisories.json");
    const db = loadAdvisories({ customPath: flags.cache ? undefined : repoPath });
    console.log(JSON.stringify(db.stats || {}, null, 2));
    return;
  }

  printHelp();
  process.exitCode = 1;
}

main().catch((err) => {
  console.error(String(err?.message || err));
  process.exit(1);
});
