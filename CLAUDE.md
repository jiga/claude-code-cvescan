# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CVEScan is a Claude Code plugin that scans `package.json` dependencies for known CVE vulnerabilities using the OSV (Open Source Vulnerabilities) API.

## Architecture

This is a Claude Code plugin, not a standalone application. It follows the Claude Code plugin structure:

- **Plugin manifest**: `.claude-plugin/plugin.json` - defines plugin metadata and entry points
- **Slash command**: `commands/cvescan.md` - the `/cvescan` command definition with inline instructions
- **Skill**: `skills/cvescan/SKILL.md` - auto-triggered skill with full scanning instructions for Claude
- **Scanner script**: `skills/cvescan/scripts/cvescan.sh` - bash script that queries OSV API

The plugin works by having Claude read package.json, query the OSV API for each dependency, and present vulnerabilities in a formatted table.

## Testing

Test fixtures are in the `tests/` directory:
- `tests/vulnerable/` - package.json with known vulnerable packages (19.1.0)
- `tests/vulnerable-parcel/` - parcel variant (19.0.0)
- `tests/vulnerable-turbopack/` - turbopack variant (19.2.0)
- `tests/fixed/` - package.json with patched versions (19.1.3)

Run the test suite:
```bash
bash tests/run-tests.sh
```

To test the scanner directly:
```bash
bash skills/cvescan/scripts/cvescan.sh tests/vulnerable/package.json
```

### Key accuracy tests
- Fix versions must match the installed version's semver branch (19.1.x -> 19.1.3, not 19.0.2)
- CVE IDs are extracted from aliases when available
- Severity uses `database_specific.severity` from OSV response

## Requirements

The scanner requires `curl` and `jq` to be installed on the system.

## OSV API Usage

The scanner queries the OSV API endpoint:
```
POST https://api.osv.dev/v1/query
{
  "package": {"name": "PACKAGE_NAME", "ecosystem": "npm"},
  "version": "VERSION"
}
```

Severity levels are derived from CVSS scores: CRITICAL (>=9), HIGH (>=7), MEDIUM (>=4), LOW (<4).
