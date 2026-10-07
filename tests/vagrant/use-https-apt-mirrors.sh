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

# Only the files apt actually reads; installer backups (e.g. *.orig) in
# sources.list.d are ignored by apt and left alone.
shopt -s nullglob
apt_source_files=()
for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  if [[ -f "$file" ]]; then
    apt_source_files+=("$file")
  fi
done

for file in "${apt_source_files[@]}"; do
  sed -i -E 's#http://(([a-z]{2}\.)?archive|security)\.ubuntu\.com/#https://\1.ubuntu.com/#g' "$file"
done

echo "Active apt sources:"
for file in "${apt_source_files[@]}"; do
  grep -HE '^(URIs:|deb )' "$file" || true
done
