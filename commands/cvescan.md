---
description: Scan package.json for known CVE vulnerabilities using the OSV database
allowed-tools: Bash, Read, Glob
---

# CVE Scan

Scan package.json for known CVE vulnerabilities.

## Arguments: $ARGUMENTS

Use the **cvescan skill** to scan for vulnerabilities. The skill will:

1. Find the package.json file (from $ARGUMENTS or current directory)
2. Query the OSV API for each dependency
3. Present vulnerabilities in a table with severity, CVE ID, and fix versions
4. Provide npm install commands to fix issues

Options:
- `--deep`: Scan full dependency tree (requires node_modules installed)
