const REDOS_PROBES = [
  `${"a".repeat(24)}!`,
  `${"0".repeat(24)}@`,
  `${" ".repeat(36)}!`,
  `${"/".repeat(24)}x`,
  `${"ab".repeat(13)}!`,
  `${"a1".repeat(13)}!`,
  `${"a_".repeat(13)}!`,
  `"pkg": "${"a".repeat(24)}`,
  `SELECT ${"a".repeat(24)} FROM`,
  `http://${"a".repeat(24)}!`,
  `req.body.${"a".repeat(24)}=`,
  `<script>${"a".repeat(24)}!`
];

const UNANCHORED_NESTED_RE = /\((?:\?:)?(?:\[[^\]]+\][+*]|\\(?:w|d|s|S|W|D)[+*]|\.[+*])\)[+*]/;

export function checkRegexSafety(patternStr, options = {}) {
  if (typeof patternStr !== "string" || !patternStr.length) {
    return { safe: false, reason: "Pattern must be a non-empty string" };
  }

  let regex;
  try {
    regex = new RegExp(patternStr);
  } catch (err) {
    return { safe: false, reason: `Invalid RegExp syntax: ${err.message}` };
  }

  if (options.strictStatic && UNANCHORED_NESTED_RE.test(patternStr)) {
    return { safe: false, reason: "Unanchored nested quantifier pattern risks catastrophic backtracking" };
  }

  const maxProbeMs = typeof options.maxProbeMs === "number" ? options.maxProbeMs : 15;
  let worstMs = 0;

  for (const probe of REDOS_PROBES) {
    const start = performance.now();
    regex.test(probe);
    const elapsed = performance.now() - start;
    if (elapsed > worstMs) worstMs = elapsed;
    if (elapsed > maxProbeMs) {
      return {
        safe: false,
        elapsedMs: Number(elapsed.toFixed(2)),
        reason: `Pattern exceeded ReDoS timing budget (${elapsed.toFixed(2)} ms > ${maxProbeMs} ms)`
      };
    }
  }

  return { safe: true, elapsedMs: Number(worstMs.toFixed(2)) };
}
