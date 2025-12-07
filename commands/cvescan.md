---
description: Scan package.json for known CVE vulnerabilities using the OSV database
allowed-tools: Bash, Read, Glob
---

# CVE Scan

Scan package.json for known CVE vulnerabilities.

## Arguments: $ARGUMENTS

## Instructions

1. **Find the CVE scanner script** by looking up the plugin installation path:
   ```bash
   jq -r '.plugins | to_entries[] | select(.key | contains("cvescan")) | .value.installPath' ~/.claude/plugins/installed_plugins.json
   ```

2. **Run the scanner** with the path from step 1:
   ```bash
   bash <PLUGIN_PATH>/skills/cvescan/scripts/cvescan.sh $ARGUMENTS
   ```

   Replace `<PLUGIN_PATH>` with the actual path returned from step 1.

3. **Parse the JSON output** and present results in a table:
   - Show total packages scanned and vulnerabilities found
   - For each vulnerability: Package, Installed Version, Severity, CVE ID, Fix Version

4. **Provide fix commands**:
   - For dependencies: `npm install package@version`
   - For devDependencies: `npm install -D package@version`

5. If no vulnerabilities found, confirm scan completed successfully.

## Options

- Default: Scans direct dependencies from package.json
- `--deep`: Scans full dependency tree (requires node_modules installed)
