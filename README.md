<p align="center">
  <img src="assets/wide-logo.png" alt="Wide Rules" width="128">
  <h1 align="center">Wide Rules</h1>
  <p align="center">The shared security rule and advisory database behind every Wide product</p>
</p>

<p align="center">
  <a href="https://github.com/sl4de0day/wide-rules/releases/latest">Release</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#building-from-source">Build</a> ·
  <a href="https://github.com/sl4de0day/wide-rules/releases">Changelog</a> ·
  <a href="https://github.com/sl4de0day/wide-ide">Wide IDE</a> ·
  <a href="https://github.com/sl4de0day/wide-cli">Wide CLI</a> ·
  <a href="https://github.com/sl4de0day/wide-app">Wide App</a> ·
  <a href="https://github.com/sl4de0day/wide-sdk">Wide SDK</a> ·
  <a href="https://github.com/sl4de0day/wide-action">Wide Action</a> ·
  <a href="LICENSE">License</a>
</p>

---

> **Wide blends web development and web security into one AI-powered workflow.** Write the code, catch the vulnerability, and test the fix in the same place.

**Wide Rules is the single source of truth for security detection across the Wide ecosystem. Its 750+ security rules cover 90+ CWE categories and the OWASP Top 10 for LLMs, backed by an OSV advisory bundle enriched with GitHub Advisories, CISA KEV, and EPSS. Wide IDE, Wide App, Wide CLI, Wide Action, and Wide SDK all ship the same rules, so a vulnerability caught in one is caught in all of them. The package also includes DecisionCore, the multi-agent coordination primitives (`CommitmentGate`, `PluralityConsensus`, `ClaimTable`, `PartitionAssignment`, `WeightedScorer`, `SynchronizationBarrier`) used by Wide's AI agents.**

Wide Rules separates security definitions from scanner engines:
- **Centralized Vulnerability Database:** 750+ curated rules maintained independently of binary release cycles.
- **Embedded DecisionCore Primitives:** Native multi-agent consensus, anti-thrashing dwell gates, and collision-free lease tables.
- **Threat Intelligence Feeds:** Integrated OSV advisory bundle enriched with GitHub Advisories across major ecosystems, CISA KEV flags, EPSS scoring, and SHA-256 integrity verification.
- **ReDoS Hardened & Linear Execution:** All rule patterns and regular expressions verified against ReDoS backtracking with dedicated benchmark validation.
- **Pre-Compiled Distribution:** Bundled into lightweight `dist/rules.json`, `dist/rules.min.json`, and `dist/osv-bundle.json` artifacts for instant offline and air-gapped scanning.
- **Ecosystem Consistency:** Powers real-time editor diagnostics in Wide IDE, terminal scans in Wide CLI, CI/CD gates in Wide Action, and programmatic audits in Wide SDK.

## Features

- **Comprehensive SAST Catalog.** 750+ curated security rules spanning SQL injection, command execution, path traversal, SSRF, memory safety, and AI prompt injection.
- **DecisionCore Multi-Agent Engine.** Out-of-the-box algorithmic coordination primitives for subagent voting, resource claiming, and patch evaluation.
- **Multi-Language Coverage.** Tailored detection patterns for JavaScript, TypeScript, Python, PHP, Java, Go, C#, Rust, and Ruby.
- **Schema Validated.** Every rule is verified against an explicit JSON Schema ensuring consistent metadata, CWE mapping, and severity rankings.
- **Pre-Compiled Distribution.** Automated CI bundling packages the complete rule catalog into standalone `dist/rules.json` and `dist/rules.min.json` for offline and air-gapped security scanning.
- **Community Extensible.** Open YAML format enabling security teams to contribute new CVE detections and custom organization policies via pull requests.

## Rule Categories

| Category | Rules | Description |
| :--- | :--- | :--- |
| `injection` | 181 | SQL injection, command injection, eval, template injection, NoSQLi, argument injection |
| `auth` | 106 | Insecure direct object references (IDOR), session fixation, authorization bypass |
| `network` | 93 | Server-side request forgery (SSRF), open redirect, CORS misconfiguration, CSRF |
| `secrets` | 76 | Hardcoded API keys, private keys, access tokens, cloud credentials |
| `deserialization` | 51 | Unsafe deserialization, XML external entity (XXE), format string vulnerabilities |
| `filesystem` | 47 | Path traversal, directory traversal, unrestricted file upload |
| `prototype` | 31 | Prototype pollution, unsafe recursive object merging |
| `xss` | 28 | Cross-site scripting, DOM manipulation, unsafe HTML output |
| `crypto` | 26 | Deprecated ciphers, collision-prone hashing, weak randomness |
| `logic` | 2 | Numeric validation flaws, integer boundary overflows |
| `ai` | 13 | AI agent prompt injection, unsafe tool execution, context overflow, untrusted MCP |
| `general` | 75 | General application security, memory safety, client-side trust issues |

## Quick Start

### Using the Pre-Compiled Bundle

Download or fetch the latest compiled bundle directly:

```bash
curl -sSL https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/rules.json -o rules.json
```

Or consume the bundle directly from GitHub via curl or as a git dependency (`npm install github:sl4de0day/wide-rules`):

```bash
curl -sSL https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/rules.min.json -o rules.min.json
```

## Authoring a Rule

Rules are authored in clean YAML format under the appropriate category directory in `rules/<category>/`:

```yaml
id: wide/sample-sqli
name: sample-sqli
category: INJECTION
severity: CRITICAL
languages:
  - js
  - ts
cwe: CWE-89
pattern: \.query\s*\(\s*["'][^"']*["']\s*\+
message: Dynamic SQL query constructed with unescaped string concatenation.
remediation: Use parameterized queries with bind variables.
```

## Building from source

Requirements:
- Node.js 20 or newer
- npm

```bash
git clone https://github.com/sl4de0day/wide-rules.git
cd wide-rules
npm install
npm run validate
npm run bundle
npm test
```

## The Wide Ecosystem

Wide blends web development and web security into one AI-powered workflow. Every product runs on the same security rules, so a vulnerability caught in one place is caught everywhere.

| Product | Who it is for |
| :--- | :--- |
| [Wide IDE](https://github.com/sl4de0day/wide-ide) | **The flagship.** A full IDE for web developers and pentesters: write code, see vulnerabilities as you type, and test them with built-in pentest tools and AI agents. |
| [Wide App](https://github.com/sl4de0day/wide-app) | A prompt-only AI workspace for people who do not need a full IDE. Describe the task; Wide's agents build, fix, and audit the project. |
| [Wide CLI](https://github.com/sl4de0day/wide-cli) | The same AI agents and security scanner in your terminal. |
| [Wide Action](https://github.com/sl4de0day/wide-action) | The same rules as a pull request security gate in GitHub CI. |
| [Wide SDK](https://github.com/sl4de0day/wide-sdk) | A Python library for building your own agents on Wide's security tooling. |
| [Wide Rules](https://github.com/sl4de0day/wide-rules) | The shared rule and advisory database behind every Wide product. |

## License

Wide Rules is free software licensed under the [MIT License](LICENSE).

Copyright (c) 2026 sl4de0day.
