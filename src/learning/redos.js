export const REDOS_PROBES = [
  "a".repeat(80) + "!",
  "a".repeat(600) + "!",
  " ".repeat(600) + "!",
  "0".repeat(600) + "x",
  "a=a".repeat(120) + "!",
  "a.b.".repeat(150) + "!",
  "http://" + "a/".repeat(250) + "?",
  "foo(" + "a,".repeat(250) + "b",
  "{ " + "a: 1, ".repeat(100) + "!",
  "SELECT " + "id, ".repeat(150) + "FROM users WHERE ",
  "<div " + "a='b' ".repeat(120) + "!",
  "\"\\\\\\\\" + "\\\\".repeat(200) + "x"
];

function isUnboundedQuantifierAt(pattern, index) {
  const ch = pattern[index];
  if (ch === "*" || ch === "+") return true;
  if (ch === "{") {
    const rest = pattern.slice(index, index + 16);
    if (/^\{\s*\d+\s*,\s*\}/.test(rest)) return true;
  }
  return false;
}

function hasStarHeightOverOne(patternStr) {
  let inClass = false;
  let escaped = false;
  const stack = [];
  for (let i = 0; i < patternStr.length; i++) {
    const c = patternStr[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c === "\\") {
      escaped = true;
      continue;
    }
    if (c === "[" && !inClass) {
      inClass = true;
      continue;
    }
    if (c === "]" && inClass) {
      inClass = false;
      continue;
    }
    if (inClass) continue;
    if (c === "(") {
      stack.push({ hasUnboundedInner: false });
    } else if (c === ")") {
      const top = stack.pop();
      if (!top) continue;
      const outerUnbounded = isUnboundedQuantifierAt(patternStr, i + 1);
      if (top.hasUnboundedInner && outerUnbounded) {
        return true;
      }
      if (stack.length > 0 && (top.hasUnboundedInner || outerUnbounded)) {
        stack[stack.length - 1].hasUnboundedInner = true;
      }
    } else if ((c === "*" || c === "+") && stack.length > 0) {
      stack[stack.length - 1].hasUnboundedInner = true;
    }
  }
  return false;
}

function hasUnanchoredQuadraticLookahead(patternStr) {
  return /^\(\?=[^)]*\.\*/.test(patternStr) || /\|\(\?=[^)]*\.\*/.test(patternStr);
}

export function checkRegexSafety(patternStr, options = {}) {
  if (!patternStr || typeof patternStr !== "string") {
    return { safe: false, reason: "Pattern must be a non-empty string", probesTested: 0, worstMs: 0 };
  }
  if (patternStr.length > 4096) {
    return { safe: false, reason: "Pattern exceeds 4096 character limit", probesTested: 0, worstMs: 0 };
  }

  let compiled;
  try {
    const flags = patternStr.includes("\\uD800") ? "" : "u";
    compiled = new RegExp(patternStr, flags);
  } catch {
    try {
      compiled = new RegExp(patternStr);
    } catch (err) {
      return {
        safe: false,
        reason: `Invalid regex syntax: ${String(err?.message || err)}`,
        probesTested: 0,
        worstMs: 0
      };
    }
  }

  const strictStatic = options.strictStatic !== false;
  if (strictStatic) {
    if (hasStarHeightOverOne(patternStr)) {
      return {
        safe: false,
        reason: "Nested unbounded quantifier pattern carries catastrophic backtracking risk",
        probesTested: 0,
        worstMs: 0
      };
    }
    if (hasUnanchoredQuadraticLookahead(patternStr)) {
      return {
        safe: false,
        reason: "Unanchored .* lookahead carries quadratic evaluation risk",
        probesTested: 0,
        worstMs: 0
      };
    }
    if (/\\(\d+)/.test(patternStr) && /[+*]/.test(patternStr)) {
      return {
        safe: false,
        reason: "Quantified pattern with backreference exceeds static complexity bounds",
        probesTested: 0,
        worstMs: 0
      };
    }
  }

  const maxProbeMs = typeof options.maxProbeMs === "number" ? options.maxProbeMs : 15;
  compiled.test("warmup_sample_text");
  let worstMs = 0;

  for (let i = 0; i < REDOS_PROBES.length; i++) {
    const start = performance.now();
    compiled.test(REDOS_PROBES[i]);
    const elapsed = performance.now() - start;
    if (elapsed > worstMs) worstMs = elapsed;
    if (elapsed > maxProbeMs) {
      return {
        safe: false,
        reason: `Regex timed out on ReDoS probe #${i + 1} (${elapsed.toFixed(1)}ms > ${maxProbeMs}ms)`,
        probesTested: i + 1,
        worstMs
      };
    }
  }

  return { safe: true, reason: null, probesTested: REDOS_PROBES.length, worstMs };
}
