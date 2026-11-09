<p align="center">
  <img src="assets/wide-logo.png" alt="Wide Rules" width="128">
  <h1 align="center">Wide Rules</h1>
  <p align="center">Unified vulnerability, AST pattern, and SAST security rule database for the Wide ecosystem</p>
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

**Wide Rules is the unified, versioned static application security testing (SAST) rule and AST pattern database for the Wide ecosystem. Housing 700+ security rules covering 90+ CWE categories across JavaScript, TypeScript, Python, Go, PHP, Java, C#, and Ruby, it acts as the central vulnerability intelligence repository for Wide IDE, Wide CLI, Wide Action, and Wide SDK.**

Wide Rules separates security definitions from scanner engines:
- **Centralized Vulnerability Database:** Over 700 curated rules maintained independently of binary release cycles.
- **Pre-Compiled Distribution:** Bundled into lightweight `dist/rules.json` and `dist/rules.min.json` artifacts for instant offline and air-gapped scanning.
- **Ecosystem Consistency:** Powers real-time editor diagnostics in Wide IDE, terminal scans in Wide CLI, CI/CD gates in Wide Action, and programmatic audits in Wide SDK.

## Features

- **Comprehensive SAST Catalog.** Over 700 curated security rules spanning SQL injection, command execution, path traversal, SSRF, memory safety, and secret detection.
- **Multi-Language Coverage.** Tailored detection patterns for JavaScript, TypeScript, Python, PHP, Java, Go, C#, Rust, and Ruby.
- **Schema Validated.** Every rule is verified against an explicit JSON Schema ensuring consistent metadata, CWE mapping, and severity rankings.
- **Pre-Compiled Distribution.** Automated CI bundling packages the complete rule catalog into standalone `dist/rules.json` and `dist/rules.min.json` for offline and air-gapped security scanning.
- **Community Extensible.** Open YAML format enabling security teams to contribute new CVE detections and custom organization policies via pull requests.

## Rule Categories

| Category | Rules | Description |
| :--- | :--- | :--- |
| `injection` | 179 | SQL injection, command injection, eval, template injection, NoSQLi, argument injection |
| `auth` | 106 | Insecure direct object references (IDOR), session fixation, authorization bypass |
| `network` | 92 | Server-side request forgery (SSRF), open redirect, CORS misconfiguration, CSRF |
| `secrets` | 75 | Hardcoded API keys, private keys, access tokens, cloud credentials |
| `deserialization` | 51 | Unsafe deserialization, XML external entity (XXE), format string vulnerabilities |
| `filesystem` | 47 | Path traversal, directory traversal, unrestricted file upload |
| `prototype` | 31 | Prototype pollution, unsafe recursive object merging |
| `xss` | 28 | Cross-site scripting, DOM manipulation, unsafe HTML output |
| `crypto` | 26 | Deprecated ciphers, collision-prone hashing, weak randomness |
| `logic` | 2 | Numeric validation flaws, integer boundary overflows |
| `general` | 75 | General application security, memory safety, client-side trust issues |

## Quick Start

### Using the Pre-Compiled Bundle

Download or fetch the latest compiled bundle directly:

```bash
curl -sSL https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/rules.json -o rules.json
```

Or consume minified distribution via curl or npm:

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

## License

Wide Rules is free software licensed under the [MIT License](LICENSE).

Copyright (c) 2026 sl4de0day.
