#!/bin/bash
# CVEScan Test Runner
# Validates scanner accuracy against test fixtures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/../skills/cvescan/scripts/cvescan.sh"

PASSED=0
FAILED=0

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo "  Expected: $2"
    echo "  Got: $3"
    FAILED=$((FAILED + 1))
}

echo "CVEScan Test Suite"
echo "=================="
echo ""

# Test 1: Vulnerable package should find CVEs
echo "Test 1: Vulnerable packages (19.1.0)"
result=$(bash "$SCANNER" "$SCRIPT_DIR/vulnerable/package.json" 2>/dev/null)
vuln_count=$(echo "$result" | jq '.vulnerable')
if [ "$vuln_count" -gt 0 ]; then
    pass "Found $vuln_count vulnerabilities in vulnerable package"
else
    fail "Should find vulnerabilities in vulnerable package" ">0" "$vuln_count"
fi

# Test 2: Fixed package should have no CVEs
echo "Test 2: Fixed packages (19.1.3)"
result=$(bash "$SCANNER" "$SCRIPT_DIR/fixed/package.json" 2>/dev/null)
vuln_count=$(echo "$result" | jq '.vulnerable')
if [ "$vuln_count" -eq 0 ]; then
    pass "No vulnerabilities in fixed package"
else
    fail "Should find 0 vulnerabilities in fixed package" "0" "$vuln_count"
fi

# Test 3: Correct fix version for 19.1.x branch
echo "Test 3: Fix version accuracy (19.1.x branch)"
result=$(bash "$SCANNER" "$SCRIPT_DIR/vulnerable/package.json" 2>/dev/null)
# Check that fix versions are in 19.1.x range, not 19.0.x
fix_versions=$(echo "$result" | jq -r '.vulnerabilities[].fix' | sort -u)
has_correct_fix=false
for fix in $fix_versions; do
    if [[ "$fix" == 19.1.* ]]; then
        has_correct_fix=true
        break
    fi
done
if [ "$has_correct_fix" = true ]; then
    pass "Fix versions correctly match 19.1.x branch"
else
    fail "Fix versions should be in 19.1.x range" "19.1.x" "$fix_versions"
fi

# Test 4: Correct fix version for 19.0.x branch
echo "Test 4: Fix version accuracy (19.0.x branch)"
result=$(bash "$SCANNER" "$SCRIPT_DIR/vulnerable-parcel/package.json" 2>/dev/null)
fix_versions=$(echo "$result" | jq -r '.vulnerabilities[].fix' | sort -u)
has_correct_fix=false
for fix in $fix_versions; do
    if [[ "$fix" == 19.0.* ]]; then
        has_correct_fix=true
        break
    fi
done
if [ "$has_correct_fix" = true ]; then
    pass "Fix versions correctly match 19.0.x branch"
else
    fail "Fix versions should be in 19.0.x range" "19.0.x" "$fix_versions"
fi

# Test 5: Correct fix version for 19.2.x branch
echo "Test 5: Fix version accuracy (19.2.x branch)"
result=$(bash "$SCANNER" "$SCRIPT_DIR/vulnerable-turbopack/package.json" 2>/dev/null)
fix_versions=$(echo "$result" | jq -r '.vulnerabilities[].fix' | sort -u)
has_correct_fix=false
for fix in $fix_versions; do
    if [[ "$fix" == 19.2.* ]]; then
        has_correct_fix=true
        break
    fi
done
if [ "$has_correct_fix" = true ]; then
    pass "Fix versions correctly match 19.2.x branch"
else
    fail "Fix versions should be in 19.2.x range" "19.2.x" "$fix_versions"
fi

# Test 6: No jq errors in output
echo "Test 6: No jq errors"
result=$(bash "$SCANNER" "$SCRIPT_DIR/vulnerable/package.json" 2>&1)
if echo "$result" | grep -q "jq: error"; then
    fail "Should not have jq errors" "no errors" "jq error found"
else
    pass "No jq errors in output"
fi

# Test 7: CVE IDs are extracted correctly
echo "Test 7: CVE ID extraction"
result=$(bash "$SCANNER" "$SCRIPT_DIR/vulnerable/package.json" 2>/dev/null)
cve_ids=$(echo "$result" | jq -r '.vulnerabilities[].cve')
has_cve=false
has_ghsa=false
for id in $cve_ids; do
    if [[ "$id" == CVE-* ]]; then
        has_cve=true
    elif [[ "$id" == GHSA-* ]]; then
        has_ghsa=true
    fi
done
if [ "$has_cve" = true ] || [ "$has_ghsa" = true ]; then
    pass "CVE/GHSA IDs extracted correctly"
else
    fail "Should extract CVE or GHSA IDs" "CVE-* or GHSA-*" "$cve_ids"
fi

# Test 8: Severity levels are valid
echo "Test 8: Severity levels"
result=$(bash "$SCANNER" "$SCRIPT_DIR/vulnerable/package.json" 2>/dev/null)
severities=$(echo "$result" | jq -r '.vulnerabilities[].severity' | sort -u)
valid=true
for sev in $severities; do
    case "$sev" in
        CRITICAL|HIGH|MODERATE|MEDIUM|LOW|UNKNOWN) ;;
        *) valid=false ;;
    esac
done
if [ "$valid" = true ]; then
    pass "Severity levels are valid"
else
    fail "Severity levels should be CRITICAL/HIGH/MEDIUM/LOW" "valid levels" "$severities"
fi

# Summary
echo ""
echo "=================="
echo "Results: $PASSED passed, $FAILED failed"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
