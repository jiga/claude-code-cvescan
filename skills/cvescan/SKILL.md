---
name: cvescan
description: Scan package.json dependencies for known CVE vulnerabilities using the OSV database. Use when reviewing package.json, checking for security issues, auditing npm dependencies, or when user mentions CVE, vulnerability, security scan, npm audit, or security review.
allowed-tools: Bash, Read, Glob, Grep
---

# CVE Scanner for package.json

Scan npm package dependencies for known security vulnerabilities using the OSV (Open Source Vulnerabilities) database.

## Instructions

When asked to scan for vulnerabilities or review package.json security:

### 1. Find and Read package.json

Use the Read tool to read the package.json file from the current directory or user-specified path.

### 2. Query OSV API for Each Dependency

For each package in `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`, query the OSV API:

```bash
curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"PACKAGE_NAME","ecosystem":"npm"},"version":"VERSION"}'
```

Example for a single package:
```bash
curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}'
```

### 3. Parse the Response

The OSV API returns vulnerabilities in this format:
```json
{
  "vulns": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "aliases": ["CVE-2021-xxxxx"],
      "summary": "Description of vulnerability",
      "severity": [{"type": "CVSS_V3", "score": "7.5"}],
      "affected": [
        {
          "ranges": [
            {
              "events": [
                {"introduced": "0"},
                {"fixed": "4.17.21"}
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

- **CVE ID**: Prefer `aliases` array entries starting with "CVE-", fall back to `id`
- **Severity**: Calculate from CVSS score (>=9 CRITICAL, >=7 HIGH, >=4 MEDIUM, <4 LOW)
- **Fix version**: Look in `affected[].ranges[].events[]` for `fixed` field

### 4. Present Results

Show results in a clear table format:

| Package | Installed | Severity | CVE ID | Summary | Fix Version |
|---------|-----------|----------|--------|---------|-------------|
| lodash  | 4.17.20   | HIGH     | CVE-2021-23337 | Command Injection | 4.17.21 |

### 5. Provide Fix Commands

```bash
# For dependencies
npm install lodash@4.17.21

# For devDependencies
npm install -D package@version
```

## Deep Scan (Full Dependency Tree)

If user requests `--deep` scan and `node_modules` exists:

```bash
npm ls --all --json
```

This returns the full dependency tree. Parse and scan each unique package@version.

## Severity Levels

| Level | CVSS Score |
|-------|------------|
| CRITICAL | >= 9.0 |
| HIGH | >= 7.0 |
| MEDIUM | >= 4.0 |
| LOW | < 4.0 |

## What Gets Scanned

- `dependencies` - Production dependencies
- `devDependencies` - Development dependencies
- `optionalDependencies` - Optional dependencies
- `peerDependencies` - Peer dependencies

## Example Workflow

1. Read package.json
2. Extract all dependencies with versions
3. For each dependency, call OSV API
4. Collect vulnerabilities
5. Present summary table
6. Suggest npm install commands for fixes

## Requirements

- `curl` - for API requests (usually pre-installed)
- Internet access to query https://api.osv.dev
