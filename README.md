# CVEScan - Claude Code Plugin

A Claude Code plugin that scans `package.json` dependencies for known CVE vulnerabilities using the [OSV (Open Source Vulnerabilities)](https://osv.dev/) database.

## Features

- Scans all dependency types: `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`
- Real-time vulnerability lookup via the OSV API
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- Actionable fix recommendations with exact version numbers
- Works with any npm/Node.js project

## Installation

### Via Plugin Marketplace

```bash
# Add the marketplace
/plugin marketplace add jiga/claude-code-cvescan

# Install the plugin
/plugin install cvescan@jiga
```

### Manual Installation

Clone this repository into your Claude Code plugins directory or add the marketplace URL directly.

## Usage

### Slash Command

```bash
# Scan package.json in current directory
/cvescan

# Scan a specific file
/cvescan path/to/package.json
```

### Skill (Auto-triggered)

The plugin also registers a skill that Claude will automatically use when you:
- Ask to "scan for vulnerabilities"
- Mention "CVE", "security scan", or "npm audit"
- Request a security review of dependencies

## Example Output

```
CVE Scan Results

File scanned: package.json

| Metric | Count |
|--------|-------|
| Total packages scanned | 45 |
| Vulnerabilities found | 2 |

Vulnerabilities

| Package | Installed | Severity | CVE ID | Fix Version |
|---------|-----------|----------|--------|-------------|
| lodash | 4.17.20 | HIGH | GHSA-xxxx | 4.17.21 |
| minimist | 1.2.5 | CRITICAL | GHSA-yyyy | 1.2.6 |

Fix Commands:
npm install lodash@4.17.21 minimist@1.2.6
```

## Requirements

- `curl` - for API requests (pre-installed on most systems)
- `jq` - for JSON parsing

### Installing jq

```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Windows (via chocolatey)
choco install jq
```

## How It Works

1. Parses the `package.json` file to extract all dependencies
2. Queries the OSV API for each package/version combination
3. Aggregates vulnerability data with severity levels
4. Presents results in a clear, actionable format

## Severity Levels

| Level | CVSS Score |
|-------|------------|
| CRITICAL | >= 9.0 |
| HIGH | >= 7.0 |
| MEDIUM | >= 4.0 |
| LOW | < 4.0 |

## Plugin Structure

```
cvescan/
├── .claude-plugin/
│   └── plugin.json          # Plugin manifest
├── commands/
│   └── cvescan.md           # Slash command definition
├── skills/
│   └── cvescan/
│       ├── SKILL.md         # Skill definition
│       └── scripts/
│           └── cvescan.sh   # Scanner script
├── README.md
└── LICENSE
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

[j2p2](https://github.com/jiga)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
