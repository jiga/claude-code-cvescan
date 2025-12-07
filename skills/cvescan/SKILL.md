---
name: cvescan
description: Scan package.json dependencies for known CVE vulnerabilities using the OSV database. Use when reviewing package.json, checking for security issues, auditing npm dependencies, or when user mentions CVE, vulnerability, security scan, npm audit, or security review.
allowed-tools: Bash, Read, Glob, Grep
---

# CVE Scanner for package.json

Scan npm package dependencies for known security vulnerabilities using the OSV (Open Source Vulnerabilities) database.

## Instructions

When asked to scan for vulnerabilities or review package.json security:

### 1. Run the Scanner

Execute the CVE scanner script:
```bash
bash scripts/cvescan.sh [path/to/package.json] [--deep]
```

**Options:**
- No arguments: scans `package.json` in current directory
- Path argument: scans specified package.json
- `--deep`: scans full dependency tree (requires node_modules)

### 2. Parse the JSON Output

The script returns:
```json
{
  "scanned": 45,
  "vulnerable": 3,
  "vulnerabilities": [
    {
      "package": "lodash",
      "installed": "4.17.20",
      "dependencyType": "dependencies",
      "cve": "CVE-2021-23337",
      "severity": "HIGH",
      "summary": "Command Injection vulnerability",
      "fix": "4.17.21"
    }
  ]
}
```

### 3. Present Results

Show a summary table:

| Package | Installed | Severity | CVE ID | Summary | Fix Version |
|---------|-----------|----------|--------|---------|-------------|
| lodash  | 4.17.20   | HIGH     | CVE-2021-23337 | Command Injection | 4.17.21 |

### 4. Provide Fix Commands

```bash
npm install lodash@4.17.21
npm install -D package@version  # for devDependencies
```

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

## Requirements

- `jq` - for JSON parsing (install with `brew install jq`)
- `curl` - for API requests (usually pre-installed)
