---
name: cvescan
description: Scan package.json dependencies for known CVE vulnerabilities using the OSV database. Use when reviewing package.json, checking for security issues, auditing npm dependencies, or when user mentions CVE, vulnerability, security scan, npm audit, or security review.
allowed-tools: Bash, Read, Glob, Grep
---

# CVE Scanner for package.json

Scan npm package dependencies for known security vulnerabilities using the OSV (Open Source Vulnerabilities) database.

## Instructions

### 1. Read package.json

Use the Read tool to get the package.json contents. Extract all dependencies from:
- `dependencies`
- `devDependencies`
- `optionalDependencies`
- `peerDependencies`

### 2. Query OSV API for Each Package

For each package, strip version prefixes (^, ~, >=) and query:

```bash
curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"PACKAGE_NAME","ecosystem":"npm"},"version":"VERSION"}'
```

Skip packages with URL versions, git refs, `*`, or `latest`.

### 3. Parse Vulnerability Response

The API returns:
```json
{
  "vulns": [{
    "id": "GHSA-xxxx",
    "aliases": ["CVE-2021-xxxxx"],
    "summary": "Description",
    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
    "affected": [{
      "ranges": [{
        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]
      }]
    }]
  }]
}
```

Extract:
- **CVE ID**: Prefer entries from `aliases` starting with "CVE-", else use `id`
- **Severity**: CVSS score >=9 CRITICAL, >=7 HIGH, >=4 MEDIUM, <4 LOW
- **Fix version**: From `affected[].ranges[].events[].fixed`

### 4. Present Results

| Package | Installed | Severity | CVE ID | Summary | Fix Version |
|---------|-----------|----------|--------|---------|-------------|

### 5. Provide Fix Commands

```bash
npm install package@fix_version
npm install -D package@fix_version  # for devDependencies
```

## Deep Scan (--deep)

If requested with `--deep` and `node_modules` exists:

```bash
npm ls --all --json 2>/dev/null
```

Parse the JSON to get all transitive dependencies, deduplicate by package@version, then scan each.

## Severity Levels

| Level | CVSS Score |
|-------|------------|
| CRITICAL | >= 9.0 |
| HIGH | >= 7.0 |
| MEDIUM | >= 4.0 |
| LOW | < 4.0 |
