#!/usr/bin/env bash
#
# Point the test VM's Ubuntu apt sources at one reachable, fast mirror.
#
# The bento box ships with plain-HTTP Canonical mirrors (us.archive.ubuntu.com,
# security.ubuntu.com). Canonical's port-80 service can fail while HTTPS keeps
# working, and Canonical's HTTPS can be slow. GitHub's runners sit in Azure,
# so the Azure mirror is tried first, then Canonical over HTTPS.
#
# The Azure mirror only serves HTTP. That's fine for integrity: apt verifies
# every index against the archive signing key (Signed-By), whatever the
# transport.
#
# The mirror is chosen once per run, so a retry on a fresh VM (see
# .github/scripts/run-vagrant-up-with-retry.sh) re-checks it. Only Ubuntu's own
# archive hosts are rewritten; repos the stack adds later (nginx.org, PPAs) are
# left as the deploy scripts configure them.
#
# Test harness only; production VMs keep their image's mirror configuration.

set -euo pipefail

azure_mirror="http://azure.archive.ubuntu.com/ubuntu"
canonical_https_mirror="https://archive.ubuntu.com/ubuntu"

# shellcheck source=/dev/null
. /etc/os-release
codename="${VERSION_CODENAME:?VERSION_CODENAME missing from /etc/os-release}"

reachable() {
  curl -fsS --connect-timeout 5 --max-time 15 -o /dev/null "$1/dists/${codename}/InRelease"
}

if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found; leaving apt sources unchanged" >&2
  mirror=""
elif reachable "$azure_mirror"; then
  mirror="$azure_mirror"
elif [[ -s /etc/ssl/certs/ca-certificates.crt ]] && reachable "$canonical_https_mirror"; then
  mirror="$canonical_https_mirror"
else
  echo "Neither the Azure mirror nor Canonical HTTPS is usable; leaving apt sources unchanged" >&2
  mirror=""
fi

# Give up on a stalled connection after 30s without data (apt's default is
# 120s), so a dead mirror fails the attempt quickly instead of hanging it.
cat > /etc/apt/apt.conf.d/80-test-mirror-timeouts <<'EOF'
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
EOF

# Only the files apt actually reads; installer backups (e.g. *.orig) in
# sources.list.d are ignored by apt and left alone.
shopt -s nullglob
apt_source_files=()
for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  if [[ -f "$file" ]]; then
    apt_source_files+=("$file")
  fi
done

if [[ -n "$mirror" ]]; then
  echo "Using Ubuntu mirror: ${mirror}"
  # Matches the box's original hosts and any mirror an earlier run chose, so
  # `vagrant provision` can switch mirrors again.
  for file in "${apt_source_files[@]}"; do
    sed -i -E "s#https?://(([a-z]{2}\\.)?archive|azure\\.archive|security)\\.ubuntu\\.com/ubuntu#${mirror}#g" "$file"
  done
fi

echo "Active apt sources:"
for file in "${apt_source_files[@]}"; do
  grep -HE '^(URIs:|deb )' "$file" || true
done
