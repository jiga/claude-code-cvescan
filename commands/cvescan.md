---
description: Scan package.json for known CVE vulnerabilities using the OSV database
allowed-tools: Bash, Read, Glob
---

# CVE Scan

Scan package.json for known CVE vulnerabilities.

## Usage

```
/cvescan [path/to/package.json] [--deep]
```

- **Default**: Scans only direct dependencies listed in package.json
- **--deep**: Scans the full dependency tree (all transitive dependencies). Requires `node_modules` to be installed.

## Instructions

1. Find the package.json file at: $ARGUMENTS (or use `package.json` in current directory if not specified)

2. Parse arguments to determine scan mode:
   - If `--deep` is present, run deep scan (full dependency tree)
   - Otherwise, run shallow scan (direct dependencies only)

3. Run the CVE scanner:
   ```bash
   bash ${CLAUDE_PLUGIN_ROOT}/skills/cvescan/scripts/cvescan.sh $ARGUMENTS
   ```

4. Parse the JSON output and present results in a clear table format:
   - Show total packages scanned
   - Show number of vulnerabilities found
   - Show scan mode (shallow/deep)
   - For each vulnerability, display: Package, Installed Version, Severity, CVE ID, Fix Version

5. Provide actionable fix commands:
   - For dependencies: `npm install package@version`
   - For devDependencies: `npm install -D package@version`
   - For transitive dependencies: Explain which direct dependency pulls it in (if known)

6. If no vulnerabilities found, confirm the scan completed successfully with a clean result.

7. If `--deep` scan fails due to missing node_modules, suggest running `npm install` first.
