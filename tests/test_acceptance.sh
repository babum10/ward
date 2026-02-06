#!/bin/bash
# Acceptance test script for ward
# This script verifies that all key functionality works correctly.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WARD="$PROJECT_DIR/ward"

echo "========================================"
echo "ward Acceptance Tests"
echo "========================================"
echo ""

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    echo "✓ $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo "✗ $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Test 1: Version check
echo "Test 1: Version check"
if $WARD --version | grep -q "ward"; then
    pass "Version command works"
else
    fail "Version command failed"
fi

# Test 2: Help check
echo "Test 2: Help check"
if $WARD --help | grep -q "demo"; then
    pass "Help shows demo command"
else
    fail "Help doesn't show demo command"
fi

# Test 3: Demo mode runs
echo "Test 3: Demo mode runs"
if $WARD demo 2>&1 | grep -q "DEMO MODE"; then
    pass "Demo mode runs"
else
    fail "Demo mode failed"
fi

# Test 4: Demo shows events
echo "Test 4: Demo shows mock events"
if $WARD demo 2>&1 | grep -q "EVENTS"; then
    pass "Demo shows events section"
else
    fail "Demo doesn't show events"
fi

# Test 5: Demo JSON output
echo "Test 5: Demo JSON output"
if $WARD --json demo 2>&1 | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    pass "Demo JSON is valid"
else
    fail "Demo JSON is invalid"
fi

# Test 6: Scan runs
echo "Test 6: Scan runs"
if $WARD scan 2>&1 | grep -q "Platform"; then
    pass "Scan runs and shows platform"
else
    fail "Scan failed"
fi

# Test 7: Status runs
echo "Test 7: Status runs"
if $WARD status 2>&1 | grep -q "Platform"; then
    pass "Status runs"
else
    fail "Status failed"
fi

# Test 8: Policy show
echo "Test 8: Policy show"
if $WARD policy show 2>&1 | grep -q "find"; then
    pass "Policy shows find rule"
else
    fail "Policy doesn't show find rule"
fi

# Test 9: Protect/uninstall cycle
echo "Test 9: Protect/uninstall cycle"
$WARD protect -y 2>&1 > /dev/null
if [ -d ~/.ward/guarded-bin ]; then
    pass "Protect creates guarded-bin directory"

    # Test 10: Wrapper exists
    echo "Test 10: Wrapper scripts created"
    if [ -x ~/.ward/guarded-bin/find ]; then
        pass "Find wrapper exists and is executable"
    else
        fail "Find wrapper not found or not executable"
    fi

    # Test 11: Dangerous pattern detection (observe-only)
    echo "Test 11: Pattern detection (observe-only)"
    RESULT=$(PATH=~/.ward/guarded-bin:$PATH find /tmp -maxdepth 0 -exec echo test \; 2>&1)
    if echo "$RESULT" | grep -q "WARNING.*dangerous"; then
        pass "Dangerous pattern detected in observe mode"
    else
        fail "Dangerous pattern not detected"
    fi

    # Test 12: Pattern blocked (enforce mode)
    echo "Test 12: Pattern blocked (enforce mode)"
    set +e
    RESULT=$(AICODE_GUARD_ENFORCE=1 PATH=~/.ward/guarded-bin:$PATH find /tmp -maxdepth 0 -exec echo test \; 2>&1)
    EXIT_CODE=$?
    set -e
    if [ $EXIT_CODE -ne 0 ] && echo "$RESULT" | grep -q "BLOCKED"; then
        pass "Dangerous pattern blocked in enforce mode"
    else
        fail "Dangerous pattern not blocked in enforce mode"
    fi

    # Clean up
    $WARD uninstall -y 2>&1 > /dev/null

    echo "Test 13: Uninstall cleans up"
    if [ ! -d ~/.ward/guarded-bin ]; then
        pass "Uninstall removed guarded-bin"
    else
        fail "Uninstall did not remove guarded-bin"
    fi
else
    fail "Protect did not create guarded-bin directory"
fi

echo ""
echo "========================================"
echo "Results: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "========================================"

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi
