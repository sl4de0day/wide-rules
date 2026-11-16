export const REDOS_PROBES = [
  "a".repeat(80) + "!",
  "a".repeat(600) + "!",
  " ".repeat(600) + "!",
  "0".repeat(600) + "x",
  "a=a".repeat(120) + "!",
  "a.b.".repeat(150) + "!",
  "foo." + "bar.".repeat(600) + "baz",
  "http://" + "a/".repeat(250) + "?",
  "foo(" + "a,".repeat(250) + "b",
  "(".repeat(1200) + "!",
  "\"/" + "a[b=".repeat(350) + "x",
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

function isDisjointRepeatedGroup(groupBody) {
  const body = groupBody.startsWith("?:") ? groupBody.slice(2) : groupBody;
  if (/\.\*|\.\+/.test(body)) return false;
  const branches = splitTopLevelAlternations(body);
  if (branches.length === 0) return false;
  if (branches.length === 1 && body === "0\\s*,\\s*") return true;
  return branches.every((branch) => isSelfDelimitedBranch(branch, branches));
}

function splitTopLevelAlternations(str) {
  const parts = [];
  let depth = 0;
  let inClass = false;
  let escaped = false;
  let start = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (escaped) { escaped = false; continue; }
    if (c === "\\") { escaped = true; continue; }
    if (c === "[" && !inClass) { inClass = true; continue; }
    if (c === "]" && inClass) { inClass = false; continue; }
    if (inClass) continue;
    if (c === "(") depth++;
    else if (c === ")" && depth > 0) depth--;
    else if (c === "|" && depth === 0) {
      parts.push(str.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(str.slice(start));
  return parts;
}

function hasNoNestedRepeat(fragment) {
  let depth = 0;
  let inClass = false;
  let escaped = false;
  let hasQuantInGroup = [];
  for (let i = 0; i < fragment.length; i++) {
    const c = fragment[i];
    if (escaped) { escaped = false; continue; }
    if (c === "\\") { escaped = true; continue; }
    if (c === "[" && !inClass) { inClass = true; continue; }
    if (c === "]" && inClass) { inClass = false; continue; }
    if (inClass) continue;
    if (c === "(") {
      depth++;
      hasQuantInGroup.push(false);
    } else if (c === ")") {
      const innerQ = hasQuantInGroup.pop() || false;
      depth = Math.max(0, depth - 1);
      if (innerQ && isUnboundedQuantifierAt(fragment, i + 1)) return false;
      if (hasQuantInGroup.length > 0 && innerQ) {
        hasQuantInGroup[hasQuantInGroup.length - 1] = true;
      }
    } else if ((c === "*" || c === "+") && hasQuantInGroup.length > 0) {
      hasQuantInGroup[hasQuantInGroup.length - 1] = true;
    }
  }
  return true;
}

function isSelfDelimitedBranch(branch, allBranches) {
  if (!branch || !hasNoNestedRepeat(branch)) return false;
  const trimmed = branch.replace(/^(?:\\s\*)+/, "");
  if (trimmed === "\\\\.") return true;
  if (/^\[\^[^\]]*\]$/.test(trimmed)) return true;
  if (/^\\\[[^\]*+]*\\\]$/.test(trimmed) || trimmed.startsWith("\\[") && trimmed.endsWith("\\]")) return true;
  if (trimmed.startsWith("\\(") && trimmed.includes("\\)") && (allBranches.includes("[^()]") || trimmed.endsWith("\\)") || trimmed.endsWith("]*"))) {
    return true;
  }
  if (trimmed.startsWith("\\.") || trimmed.startsWith("(?:->|\\.)") || trimmed.startsWith("\\->") || trimmed.startsWith("\\/")) {
    return true;
  }
  if (/^,(?:\\s\*)*(?:\(\?:)?(?:['"`\\])/.test(trimmed)) {
    return true;
  }
  if (trimmed.endsWith("\\/") && !trimmed.slice(0, -2).includes("/")) {
    return true;
  }
  if (branch.startsWith("(?:") && branch.endsWith(")")) {
    return isDisjointRepeatedGroup(branch);
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
      stack.push({ startIndex: i, hasUnboundedInner: false });
    } else if (c === ")") {
      const top = stack.pop();
      if (!top) continue;
      const outerUnbounded = isUnboundedQuantifierAt(patternStr, i + 1);
      const groupBody = patternStr.slice(top.startIndex + 1, i);
      const safeDisjoint = outerUnbounded && isDisjointRepeatedGroup(groupBody);
      if (top.hasUnboundedInner && outerUnbounded && !safeDisjoint) {
        return true;
      }
      if (stack.length > 0 && (top.hasUnboundedInner || (outerUnbounded && !safeDisjoint))) {
        stack[stack.length - 1].hasUnboundedInner = true;
      }
    } else if ((c === "*" || c === "+") && stack.length > 0) {
      stack[stack.length - 1].hasUnboundedInner = true;
    } else if (c === "{" && stack.length > 0) {
      if (isUnboundedQuantifierAt(patternStr, i)) {
        stack[stack.length - 1].hasUnboundedInner = true;
      }
    }
  }
  return false;
}

function hasUnsafeBackreference(patternStr) {
  if (!/\\(\d+)/.test(patternStr)) return false;
  const captures = [];
  let inClass = false;
  let escaped = false;
  const openStack = [];
  for (let i = 0; i < patternStr.length; i++) {
    const c = patternStr[i];
    if (escaped) { escaped = false; continue; }
    if (c === "\\") { escaped = true; continue; }
    if (c === "[" && !inClass) { inClass = true; continue; }
    if (c === "]" && inClass) { inClass = false; continue; }
    if (inClass) continue;
    if (c === "(") {
      const isCapturing = patternStr[i + 1] !== "?";
      const captureIdx = isCapturing ? captures.length : -1;
      if (isCapturing) captures.push("");
      openStack.push({ start: i, captureIdx });
    } else if (c === ")" && openStack.length > 0) {
      const frame = openStack.pop();
      if (frame.captureIdx >= 0) {
        captures[frame.captureIdx] = patternStr.slice(frame.start + 1, i);
      }
    }
  }

  let hasDangerousRef = false;
  const wildcardMatches = patternStr.match(/(?:\.\*|\.\+|\(\?:\(?!\\\d+\)\.\)\*)/g) || [];
  if (wildcardMatches.length >= 3) {
    return true;
  }

  const refRe = /\\([1-9]\d*)(?:([+*?])|\{\s*\d+\s*,\s*\})?/g;
  let match;
  while ((match = refRe.exec(patternStr)) !== null) {
    const idx = Number(match[1]) - 1;
    const quant = match[2] || (match[0].includes("{") ? "{" : "");
    if (quant === "+" || quant === "*" || quant === "{") {
      hasDangerousRef = true;
      break;
    }
    const body = captures[idx] ?? "";
    if (!body) {
      hasDangerousRef = true;
      break;
    }
    const isSingleCharSet = /^\[[^\]^]+\]$|^\[[^\]^]+\]\??$/.test(body) && !/[+*]/.test(body);
    const hasNestedWildcard = /\.\*|\.\+/.test(body);
    if (hasNestedWildcard) {
      hasDangerousRef = true;
      break;
    }
    if (!isSingleCharSet && /[*+]/.test(patternStr.slice(Math.max(0, match.index - 24), match.index))) {
      if (/\(\?:\.\*\)/.test(patternStr)) {
        hasDangerousRef = true;
        break;
      }
    }
  }
  return hasDangerousRef;
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
    if (hasUnsafeBackreference(patternStr)) {
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
