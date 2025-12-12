#!/bin/bash
# CVEScan - Scan package.json dependencies for known CVE vulnerabilities
# Uses the OSV (Open Source Vulnerabilities) API
#
# Usage: cvescan.sh [package.json] [--deep]
#   --deep: Scan full dependency tree (requires node_modules to be installed)

set -e

# Cleanup handler for temp files
RESULTS_FILE=""
SEEN_FILE=""
cleanup() {
    rm -f "$RESULTS_FILE" "$SEEN_FILE" 2>/dev/null
}
trap cleanup EXIT INT TERM

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
    local v="$1"
    # Remove common prefixes: ^, ~, >=, <=, >, <, =
    v=$(echo "$v" | sed -E 's/^[\^~>=<]+//')
    # If it still contains spaces or complex operators, return empty (can't resolve)
    if [[ "$v" =~ [\ \|] ]] || [[ "$v" == *"||"* ]]; then
        echo ""
        return
    fi
    # Remove any trailing range parts (e.g., "1.2.3 - 2.0.0" -> "1.2.3")
    echo "$v" | sed -E 's/\s.*$//'
}

# Function to query OSV API for a package with timeout and retry
query_osv() {
    local pkg="$1"
    local version="$2"
    local retries=3
    local delay=1
    local response=""

    for ((attempt=1; attempt<=retries; attempt++)); do
        response=$(curl -s --max-time 30 -X POST "https://api.osv.dev/v1/query" \
            -H "Content-Type: application/json" \
            -d "{\"package\":{\"name\":\"$pkg\",\"ecosystem\":\"npm\"},\"version\":\"$version\"}" \
            2>/dev/null) || true

        # Check if we got a valid JSON response
        if [ -n "$response" ] && echo "$response" | jq -e . >/dev/null 2>&1; then
            echo "$response"
            return 0
        fi

        # Wait before retry with exponential backoff
        if [ $attempt -lt $retries ]; then
            sleep $delay
            delay=$((delay * 2))
        fi
    done

    # Return empty object on failure
    echo '{}'
}

# Function to compare semver versions (returns 0 if v1 >= v2, 1 otherwise)
# Simplified comparison - compares major.minor.patch numerically
semver_gte() {
    local v1="$1"
    local v2="$2"

    # Extract major.minor.patch, ignoring prerelease tags
    local v1_base=$(echo "$v1" | sed -E 's/[-+].*//')
    local v2_base=$(echo "$v2" | sed -E 's/[-+].*//')

    # Split into components
    IFS='.' read -r v1_major v1_minor v1_patch <<< "$v1_base"
    IFS='.' read -r v2_major v2_minor v2_patch <<< "$v2_base"

    # Default to 0 if empty
    v1_major=${v1_major:-0}; v1_minor=${v1_minor:-0}; v1_patch=${v1_patch:-0}
    v2_major=${v2_major:-0}; v2_minor=${v2_minor:-0}; v2_patch=${v2_patch:-0}

    # Compare
    if [ "$v1_major" -gt "$v2_major" ] 2>/dev/null; then return 0; fi
    if [ "$v1_major" -lt "$v2_major" ] 2>/dev/null; then return 1; fi
    if [ "$v1_minor" -gt "$v2_minor" ] 2>/dev/null; then return 0; fi
    if [ "$v1_minor" -lt "$v2_minor" ] 2>/dev/null; then return 1; fi
    if [ "$v1_patch" -ge "$v2_patch" ] 2>/dev/null; then return 0; fi
    return 1
}

# Function to extract fix version from OSV response for a specific installed version
# Finds the affected range that contains the installed version and returns its fix
get_fix_version() {
    local vuln="$1"
    local installed="$2"
    local pkg_name="$3"

    # Extract all affected ranges for this package with introduced and fixed versions
    local ranges=$(echo "$vuln" | jq -r --arg pkg "$pkg_name" '
        .affected[]? |
        select(.package.name == $pkg) |
        .ranges[]? |
        select(.type == "SEMVER") |
        .events as $events |
        ([$events[]? | select(.introduced != null) | .introduced] | first) as $intro |
        ([$events[]? | select(.fixed != null) | .fixed] | first) as $fix |
        select($intro != null and $fix != null) |
        "\($intro)|\($fix)"
    ' 2>/dev/null)

    # Find the range where installed version falls
    local best_fix=""
    while IFS='|' read -r introduced fixed; do
        [ -z "$introduced" ] && continue
        [ -z "$fixed" ] && continue

        # Check if installed >= introduced AND installed < fixed
        if semver_gte "$installed" "$introduced"; then
            # This range's introduced version is <= installed
            # Check if this is a better match (higher introduced version = more specific)
            if [ -z "$best_fix" ]; then
                best_fix="$fixed"
            else
                # Prefer the fix from the range with higher introduced version
                local current_intro=$(echo "$ranges" | grep "|$best_fix$" | head -1 | cut -d'|' -f1)
                if semver_gte "$introduced" "$current_intro" 2>/dev/null; then
                    best_fix="$fixed"
                fi
            fi
        fi
    done <<< "$ranges"

    if [ -n "$best_fix" ]; then
        echo "$best_fix"
    else
        # Fallback: just get the first fix version available
        echo "$vuln" | jq -r '
            [.affected[]? | .ranges[]? | .events[]? | select(.fixed != null) | .fixed] | first // "No fix available"'
    fi
}

# Function to get severity from OSV response
get_severity() {
    local vuln="$1"
    # First try database_specific.severity (already a string like "HIGH", "CRITICAL")
    # Then try to parse CVSS vector string to extract base score
    echo "$vuln" | jq -r '
        .database_specific.severity //
        (
            (.severity[]? | select(.type == "CVSS_V3" or .type == "CVSS_V4") | .score) as $cvss |
            if $cvss then
                # CVSS vector format: "CVSS:3.1/AV:N/AC:L/..." - we need to calculate from metrics
                # Or it might be just the score number in some cases
                # Try to extract numeric score if present, otherwise use the severity string
                if ($cvss | type) == "number" then
                    if $cvss >= 9 then "CRITICAL"
                    elif $cvss >= 7 then "HIGH"
                    elif $cvss >= 4 then "MEDIUM"
                    else "LOW"
                    end
                else
                    # Its a vector string - map common patterns
                    if ($cvss | contains("A:H") or contains("I:H") or contains("C:H")) and ($cvss | contains("S:C")) then "CRITICAL"
                    elif ($cvss | contains("A:H")) or (($cvss | contains("I:H") or contains("C:H")) and ($cvss | contains("AC:L"))) then "HIGH"
                    elif ($cvss | contains("A:L") or contains("I:L") or contains("C:L")) then "MEDIUM"
                    else "LOW"
                    end
                end
            else "UNKNOWN"
            end
        ) // "UNKNOWN"'
}

# Process a single package
process_package() {
    local pkg="$1"
    local version="$2"
    local dep_type="$3"

    # Strip version prefix
    local clean_version=$(strip_version "$version")

    # Skip if version couldn't be resolved (complex ranges)
    if [ -z "$clean_version" ]; then
        echo "Warning: Skipping $pkg - complex version range '$version' cannot be resolved without lock file" >&2
        return
    fi

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

            # Extract CVE ID: prefer CVE- prefixed alias, fall back to primary ID (GHSA)
            local vuln_id=$(echo "$vuln" | jq -r '
                if .aliases then
                    (.aliases | map(select(startswith("CVE-"))) | first) // .id
                else
                    .id
                end // "UNKNOWN"')

            local summary=$(echo "$vuln" | jq -r '(.summary // .details // "No description available") | .[0:200]')
            local severity=$(get_severity "$vuln")
            local fix=$(get_fix_version "$vuln" "$clean_version" "$pkg")

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
