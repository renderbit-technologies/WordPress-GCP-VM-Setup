#!/bin/bash
set -euo pipefail

# Import the function to test
# We source the file but main execution is guarded.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Mock variables required by the sourced script
export DOMAIN="test.local"

# We source the script to test its functions.
# SC1091 is disabled because the path is dynamic and ShellCheck struggles to follow it in CI.
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/run-on-runner.sh"

# Test Helper
assert_contains() {
  local file=$1
  local pattern=$2
  if ! grep -q "$pattern" "$file"; then
    echo "Assertion failed: $file does not contain '$pattern'"
    cat "$file"
    exit 1
  fi
}

assert_count() {
  local file=$1
  local pattern=$2
  local expected=$3
  local count
  count=$(grep -c "$pattern" "$file" || echo 0)
  if [ "$count" -ne "$expected" ]; then
    echo "Assertion failed: $file contains '$pattern' $count times, expected $expected"
    cat "$file"
    exit 1
  fi
}

# Setup temp hosts file
TMP_HOSTS=$(mktemp)
trap 'rm -f "${TMP_HOSTS}"' EXIT

echo "Testing append_host_entry..."

# Test 1: Add a new host to an empty file
echo "Test 1: Add new host to empty file"
append_host_entry "test.local" "${TMP_HOSTS}"
assert_contains "${TMP_HOSTS}" "^127\.0\.0\.1 test\.local$"

# Test 2: Idempotency - add same host again
echo "Test 2: Idempotency"
append_host_entry "test.local" "${TMP_HOSTS}"
assert_count "${TMP_HOSTS}" "test\.local" 1

# Test 3: Add another host
echo "Test 3: Add second host"
append_host_entry "other.local" "${TMP_HOSTS}"
assert_contains "${TMP_HOSTS}" "^127\.0\.0\.1 other\.local$"
assert_count "${TMP_HOSTS}" "127\.0\.0\.1" 2

# Test 4: Handle partial matches (should not match)
echo "Test 4: Avoid partial matches"
append_host_entry "test" "${TMP_HOSTS}"
assert_contains "${TMP_HOSTS}" "^127\.0\.0\.1 test$"
assert_count "${TMP_HOSTS}" "127\.0\.0\.1" 3

# Test 5: Existing entry with multiple spaces
echo "Test 5: Match existing entry with multiple spaces"
echo "127.0.0.1   spaced.local" >> "${TMP_HOSTS}"
append_host_entry "spaced.local" "${TMP_HOSTS}"
assert_count "${TMP_HOSTS}" "spaced\.local" 1

# Test 6: Existing entry with tabs
echo "Test 6: Match existing entry with tabs"
printf "127.0.0.1\tmatched-tab.local\n" >> "${TMP_HOSTS}"
append_host_entry "matched-tab.local" "${TMP_HOSTS}"
assert_count "${TMP_HOSTS}" "matched-tab\.local" 1

# Test 7: Entry already in a list (though our function adds it separately, it shouldn't re-add if it's there)
echo "Test 7: Host already in a list on 127.0.0.1 line"
echo "127.0.0.1 localhost inlist.local" >> "${TMP_HOSTS}"
append_host_entry "inlist.local" "${TMP_HOSTS}"
assert_count "${TMP_HOSTS}" "inlist\.local" 1

echo "All tests passed successfully!"
