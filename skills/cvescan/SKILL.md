---
name: cvescan
description: Scan package.json dependencies for known CVE vulnerabilities using the OSV database. Use when reviewing package.json, checking for security issues, auditing npm dependencies, or when user mentions CVE, vulnerability, security scan, npm audit, or security review.
allowed-tools: Bash, Read, Glob, Grep
---

# CVE Scanner for package.json

Scan npm package dependencies for known security vulnerabilities using the OSV (Open Source Vulnerabilities) database.

## Instructions

When asked to scan for vulnerabilities or review package.json security:

1. **Find the package.json file**
   - Look in the current directory or user-specified path
   - Read the file to understand the project's dependencies

2. **Run the CVE scanner**
   ```bash
   PLUGIN_ROOT=$(jq -r '.plugins | to_entries[] | select(.key | contains("cvescan")) | .value.installPath' ~/.claude/plugins/installed_plugins.json 2>/dev/null) && bash "$PLUGIN_ROOT/skills/cvescan/scripts/cvescan.sh" [path/to/package.json]
   ```

   If no path is provided, it defaults to `package.json` in the current directory.

3. **Parse the JSON output**
   The script returns JSON with this structure:
   ```json
   {
     "scanned": 45,
     "vulnerable": 3,
     "vulnerabilities": [
       {
         "package": "lodash",
         "installed": "4.17.20",
         "dependencyType": "dependencies",
         "cve": "GHSA-xxxx-xxxx-xxxx",
         "severity": "HIGH",
         "summary": "Description of the vulnerability",
         "fix": "4.17.21"
       }
     ]
   }
   ```

4. **Present results clearly**

   If vulnerabilities are found, present them in a table:

   | Package | Installed | Severity | CVE | Fix Version |
   |---------|-----------|----------|-----|-------------|
   | lodash  | 4.17.20   | HIGH     | GHSA-xxx | 4.17.21 |

5. **Suggest fixes**

   For each vulnerability with an available fix:
   - Show the exact version to upgrade to
   - Provide the npm command: `npm install package@version`
   - If it's a devDependency: `npm install -D package@version`
   - Warn about potential breaking changes for major version bumps

## What Gets Scanned

- `dependencies` - Production dependencies
- `devDependencies` - Development dependencies
- `optionalDependencies` - Optional dependencies
- `peerDependencies` - Peer dependencies

## Severity Levels

- **CRITICAL** - CVSS score >= 9.0
- **HIGH** - CVSS score >= 7.0
- **MEDIUM** - CVSS score >= 4.0
- **LOW** - CVSS score < 4.0

## Example Response

After scanning, provide a summary like:

```
Scanned 45 packages, found 3 vulnerabilities:

| Package | Version | Severity | Issue | Fix |
|---------|---------|----------|-------|-----|
| lodash | 4.17.20 | HIGH | Command Injection | 4.17.21 |
| minimist | 1.2.5 | CRITICAL | Prototype Pollution | 1.2.6 |

Recommended fixes:
npm install lodash@4.17.21 minimist@1.2.6
```

## Requirements

The scanner requires:
- `curl` - for API requests
- `jq` - for JSON parsing (install with `brew install jq` on macOS)
