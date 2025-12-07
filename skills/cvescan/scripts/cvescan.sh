#!/bin/bash
# CVEScan - Scan package.json dependencies for known CVE vulnerabilities
# Uses the OSV (Open Source Vulnerabilities) API

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

# Get package.json path from argument or use default
PACKAGE_JSON="${1:-package.json}"

if [ ! -f "$PACKAGE_JSON" ]; then
    echo "{\"error\": \"File not found: $PACKAGE_JSON\"}" >&2
    exit 1
fi

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

            local vuln_id=$(echo "$vuln" | jq -r '.id // "UNKNOWN"')
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

# Process all dependency types
for dep_type in dependencies devDependencies optionalDependencies peerDependencies; do
    deps=$(jq -r ".$dep_type // {} | to_entries[] | \"\(.key)|\(.value)\"" "$PACKAGE_JSON" 2>/dev/null || true)

    if [ -n "$deps" ]; then
        while IFS='|' read -r pkg version; do
            [ -z "$pkg" ] && continue
            process_package "$pkg" "$version" "$dep_type"
        done <<< "$deps"
    fi
done

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
