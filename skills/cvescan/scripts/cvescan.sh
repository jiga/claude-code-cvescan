#!/bin/bash
# CVEScan - Scan package.json dependencies for known CVE vulnerabilities
# Uses the OSV (Open Source Vulnerabilities) API
#
# Usage: cvescan.sh [package.json] [--deep]
#   --deep: Scan full dependency tree (requires node_modules to be installed)

set -e

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo '{"error": "jq is required but not installed. Install with: brew install jq"}' >&2
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo '{"error": "curl is required but not installed"}' >&2
    exit 1
fi

# Parse arguments
PACKAGE_JSON="package.json"
DEEP_SCAN=false

for arg in "$@"; do
    case $arg in
        --deep)
            DEEP_SCAN=true
            ;;
        *)
            if [ -f "$arg" ]; then
                PACKAGE_JSON="$arg"
            fi
            ;;
    esac
done

if [ ! -f "$PACKAGE_JSON" ]; then
    echo "{\"error\": \"File not found: $PACKAGE_JSON\"}" >&2
    exit 1
fi

# Get the directory containing package.json for npm commands
PACKAGE_DIR=$(dirname "$PACKAGE_JSON")

# Create temp file for results
RESULTS_FILE=$(mktemp)
echo "[]" > "$RESULTS_FILE"

SCANNED=0

# Function to strip semver prefixes and get base version
strip_version() {
    echo "$1" | sed -E 's/^[\^~>=<]*//; s/\s.*$//'
}

# Function to query OSV API for a package
query_osv() {
    local pkg="$1"
    local version="$2"

    curl -s -X POST "https://api.osv.dev/v1/query" \
        -H "Content-Type: application/json" \
        -d "{\"package\":{\"name\":\"$pkg\",\"ecosystem\":\"npm\"},\"version\":\"$version\"}" \
        2>/dev/null
}

# Function to extract fix version from OSV response
get_fix_version() {
    local vuln="$1"
    echo "$vuln" | jq -r '
        [.affected[]? | .ranges[]? | .events[]? | select(.fixed != null) | .fixed] | first // "No fix available"'
}

# Function to get severity from OSV response
get_severity() {
    local vuln="$1"
    echo "$vuln" | jq -r '
        .database_specific.severity //
        (if .severity then
            (.severity[] | select(.type == "CVSS_V3") | .score) as $score |
            if $score >= 9 then "CRITICAL"
            elif $score >= 7 then "HIGH"
            elif $score >= 4 then "MEDIUM"
            else "LOW"
            end
        else "UNKNOWN" end) // "UNKNOWN"'
}

# Process a single package
process_package() {
    local pkg="$1"
    local version="$2"
    local dep_type="$3"

    # Strip version prefix
    local clean_version=$(strip_version "$version")

    # Skip if version is a URL, git ref, or file path
    if [[ "$clean_version" =~ ^(http|git|file|github:|/) ]] || [[ "$version" == "latest" ]] || [[ "$version" == "*" ]]; then
        return
    fi

    SCANNED=$((SCANNED + 1))

    # Query OSV API
    local response=$(query_osv "$pkg" "$clean_version")

    # Check if there are vulnerabilities
    local vuln_count=$(echo "$response" | jq '.vulns | length' 2>/dev/null || echo "0")

    if [ "$vuln_count" != "0" ] && [ "$vuln_count" != "null" ] && [ -n "$vuln_count" ]; then
        # Process each vulnerability
        local num_vulns=$(echo "$response" | jq '.vulns | length')
        for ((i=0; i<num_vulns; i++)); do
            local vuln=$(echo "$response" | jq -c ".vulns[$i]")

            # Prefer CVE ID from aliases, fall back to primary ID (often GHSA)
            local vuln_id=$(echo "$vuln" | jq -r '
                (.aliases // []) | map(select(startswith("CVE-"))) | first // .id // "UNKNOWN"')
            # If jq returned just the filter (no CVE found), use the primary id
            if [ "$vuln_id" = "null" ] || [ -z "$vuln_id" ]; then
                vuln_id=$(echo "$vuln" | jq -r '.id // "UNKNOWN"')
            fi
            local summary=$(echo "$vuln" | jq -r '(.summary // .details // "No description available") | .[0:200]')
            local severity=$(get_severity "$vuln")
            local fix=$(get_fix_version "$vuln")

            # Add to results file
            local current=$(cat "$RESULTS_FILE")
            echo "$current" | jq \
                --arg pkg "$pkg" \
                --arg installed "$clean_version" \
                --arg dep_type "$dep_type" \
                --arg cve "$vuln_id" \
                --arg severity "$severity" \
                --arg summary "$summary" \
                --arg fix "$fix" \
                '. += [{
                    "package": $pkg,
                    "installed": $installed,
                    "dependencyType": $dep_type,
                    "cve": $cve,
                    "severity": $severity,
                    "summary": $summary,
                    "fix": $fix
                }]' > "$RESULTS_FILE"
        done
    fi
}

# Function to recursively extract packages from npm ls JSON output
extract_packages_from_npm_ls() {
    local json="$1"
    local dep_type="$2"

    # Extract name and version from current level, then recurse into dependencies
    echo "$json" | jq -r --arg dep_type "$dep_type" '
        def extract_deps($type):
            if . == null then empty
            else
                to_entries[] |
                "\(.key)|\(.value.version // "unknown")|\($type)",
                (.value.dependencies // {} | extract_deps($type))
            end;

        .dependencies // {} | extract_deps($dep_type)
    ' 2>/dev/null || true
}

if [ "$DEEP_SCAN" = true ]; then
    # Deep scan: use npm ls to get full dependency tree
    if ! command -v npm &> /dev/null; then
        echo '{"error": "npm is required for --deep scan but not installed"}' >&2
        exit 1
    fi

    # Check if node_modules exists
    if [ ! -d "$PACKAGE_DIR/node_modules" ]; then
        echo "{\"error\": \"node_modules not found in $PACKAGE_DIR. Run 'npm install' first for --deep scan.\"}" >&2
        exit 1
    fi

    # Get production dependencies
    prod_deps=$(cd "$PACKAGE_DIR" && npm ls --all --json 2>/dev/null || echo '{}')
    deps=$(extract_packages_from_npm_ls "$prod_deps" "transitive")

    if [ -n "$deps" ]; then
        # Create temp file for deduplication (compatible with bash 3.x)
        SEEN_FILE=$(mktemp)

        while IFS='|' read -r pkg version dep_type; do
            [ -z "$pkg" ] && continue
            [ -z "$version" ] && continue
            [ "$version" = "unknown" ] && continue

            key="${pkg}@${version}"
            # Check if we've already seen this package@version
            if ! grep -qxF "$key" "$SEEN_FILE" 2>/dev/null; then
                echo "$key" >> "$SEEN_FILE"
                process_package "$pkg" "$version" "$dep_type"
            fi
        done <<< "$deps"

        rm -f "$SEEN_FILE"
    fi
else
    # Shallow scan: only direct dependencies from package.json
    for dep_type in dependencies devDependencies optionalDependencies peerDependencies; do
        deps=$(jq -r ".$dep_type // {} | to_entries[] | \"\(.key)|\(.value)\"" "$PACKAGE_JSON" 2>/dev/null || true)

        if [ -n "$deps" ]; then
            while IFS='|' read -r pkg version; do
                [ -z "$pkg" ] && continue
                process_package "$pkg" "$version" "$dep_type"
            done <<< "$deps"
        fi
    done
fi

# Read final results
RESULTS=$(cat "$RESULTS_FILE")
VULNERABLE=$(echo "$RESULTS" | jq 'length')

# Cleanup
rm -f "$RESULTS_FILE"

# Output final JSON
jq -n \
    --argjson scanned "$SCANNED" \
    --argjson vulnerable "$VULNERABLE" \
    --argjson vulnerabilities "$RESULTS" \
    '{
        "scanned": $scanned,
        "vulnerable": $vulnerable,
        "vulnerabilities": $vulnerabilities
    }'
