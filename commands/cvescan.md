---
description: Scan package.json for known CVE vulnerabilities using the OSV database
allowed-tools: Bash, Read, Glob
---

# CVE Scan

Scan package.json for known CVE vulnerabilities.

## Arguments: $ARGUMENTS

## Instructions

1. **Run the CVE scanner**:
   ```bash
   bash scripts/cvescan.sh $ARGUMENTS
   ```

2. **Parse the JSON output** and present results in a table:
   - Show total packages scanned and vulnerabilities found
   - For each vulnerability: Package, Installed Version, Severity, CVE ID, Fix Version

3. **Provide fix commands**:
   - For dependencies: `npm install package@version`
   - For devDependencies: `npm install -D package@version`

4. If no vulnerabilities found, confirm scan completed successfully.

## Options

- Default: Scans direct dependencies from package.json
- `--deep`: Scans full dependency tree (requires node_modules installed)
