---
description: Scan package.json for known CVE vulnerabilities using the OSV database
allowed-tools: Bash, Read, Glob
---

# CVE Scan

Scan package.json for known CVE vulnerabilities using the OSV (Open Source Vulnerabilities) database.

## Arguments

$ARGUMENTS

- If a path is provided, scan that package.json
- If `--deep` is included, scan full dependency tree (requires node_modules)
- Default: scan `package.json` in current directory

## Instructions

### 1. Read package.json

Use the Read tool to read the package.json file (from $ARGUMENTS path or current directory).

### 2. Scan Dependencies

For each package in `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`, query the OSV API:

```bash
curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"PACKAGE_NAME","ecosystem":"npm"},"version":"VERSION"}'
```

Strip version prefixes (^, ~, >=) before querying. Skip URLs, git refs, and `*` versions.

### 3. Parse Vulnerabilities

From the OSV response:
- **CVE ID**: Use `aliases[]` entries starting with "CVE-", or fall back to `id`
- **Severity**: From CVSS score: >=9 CRITICAL, >=7 HIGH, >=4 MEDIUM, <4 LOW
- **Fix version**: From `affected[].ranges[].events[].fixed`

### 4. Present Results

Show a summary table:

| Package | Installed | Severity | CVE ID | Summary | Fix Version |
|---------|-----------|----------|--------|---------|-------------|

### 5. Provide Fix Commands

```bash
npm install package@fix_version
npm install -D package@fix_version  # for devDependencies
```

### Deep Scan (--deep flag)

If `--deep` is requested:
1. Check if `node_modules` exists
2. Run `npm ls --all --json` to get full dependency tree
3. Scan each unique package@version combination
4. Report which packages are transitive dependencies

## No Vulnerabilities

If no vulnerabilities found, report:
```
✓ Scanned X packages - no vulnerabilities found
```
