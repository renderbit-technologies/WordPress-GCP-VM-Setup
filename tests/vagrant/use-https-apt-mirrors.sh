#!/usr/bin/env bash
#
# Point the test VM's Ubuntu apt sources at HTTPS.
#
# The bento box ships with plain-HTTP Canonical mirrors (us.archive.ubuntu.com,
# security.ubuntu.com). Canonical's port-80 service can go down while HTTPS
# keeps working, which fails every Vagrant test at the first apt-get install.
# Only Canonical hosts are rewritten; repos the stack adds later (nginx.org,
# PPAs) are left as the deploy scripts configure them.
#
# Test harness only; production VMs keep their image's mirror configuration.

set -euo pipefail

if [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
  echo "ca-certificates missing; leaving apt sources on HTTP" >&2
  exit 0
fi

shopt -s nullglob
for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [[ -f "$file" ]] || continue
  sed -i -E 's#http://(([a-z]{2}\.)?archive|security)\.ubuntu\.com/#https://\1.ubuntu.com/#g' "$file"
done

echo "Ubuntu apt sources:"
grep -rhE '^(URIs:|deb )' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | sort -u || true
