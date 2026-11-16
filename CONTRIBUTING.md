# Contributing to Wide Rules

Thank you for contributing security rules and improvements to Wide Rules.

## Rule Requirements

Every rule file under `rules/<category>/<name>.yml` must comply with `schemas/rule.schema.json`:

- Unique `id` matching `^wide/[a-z0-9_-]+$`
- Valid `category` (`INJECTION`, `AUTH`, `NETWORK`, `SECRETS`, `DESERIALIZATION`, `FILESYSTEM`, `PROTOTYPE`, `XSS`, `CRYPTO`, `AI_SECURITY`, `LOGIC`, `GENERAL`)
- Valid `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- Non-empty `languages`, `message`, `why`, and `remediation`
- Linear-time regexes passing strict static ReDoS checks (`strictStatic: true`)
- A `tests` block with realistic `positive` and `negative` samples whenever adding or modifying rules

## Local Verification

Run these checks before opening a pull request:

```bash
npm install
npm run validate
npm run bundle
npm test
npm run bench
```

Do not use emojis in rule messages, instructions, commit messages, or pull request descriptions.
