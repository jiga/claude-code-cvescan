---
description: Scan package.json for known CVE vulnerabilities using the OSV database
allowed-tools: Bash, Read, Glob
---

# CVE Scan

Scan package.json for known CVE vulnerabilities.

## Instructions

1. Find the package.json file at: $ARGUMENTS (or use `package.json` in current directory if not specified)

2. Run the CVE scanner:
   ```bash
   bash skills/cvescan/scripts/cvescan.sh "$ARGUMENTS"
   ```

3. Parse the JSON output and present results in a clear table format:
   - Show total packages scanned
   - Show number of vulnerabilities found
   - For each vulnerability, display: Package, Installed Version, Severity, CVE ID, Fix Version

4. Provide actionable fix commands:
   - For dependencies: `npm install package@version`
   - For devDependencies: `npm install -D package@version`

5. If no vulnerabilities found, confirm the scan completed successfully with a clean result.
