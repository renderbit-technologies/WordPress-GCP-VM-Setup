#!/usr/bin/env bash

set -euo pipefail

workdir="${1:?usage: run-vagrant-up-with-retry.sh <workdir> [provider]}"
provider="${2:-virtualbox}"
attempts="${VAGRANT_UP_ATTEMPTS:-2}"
retry_delay="${VAGRANT_UP_RETRY_DELAY_SECONDS:-30}"

cd "$workdir"

print_diagnostics() {
  echo "::group::Vagrant diagnostics"
  vagrant status || true

  if command -v VBoxManage >/dev/null 2>&1; then
    VBoxManage list runningvms || true
    VBoxManage list vms || true
  fi

  if [[ -d .vagrant ]]; then
    find .vagrant -maxdepth 3 -type f | sort || true
  fi

  echo "::endgroup::"
}

cleanup_failed_attempt() {
  echo "::group::Cleaning up failed Vagrant attempt"
  vagrant halt -f || true
  vagrant destroy -f || true

  if command -v VBoxManage >/dev/null 2>&1; then
    VBoxManage list runningvms || true
  fi

  echo "::endgroup::"
}

for attempt in $(seq 1 "$attempts"); do
  log_file="${RUNNER_TEMP:-/tmp}/vagrant-up-$(basename "$workdir")-attempt-${attempt}.log"

  echo "Starting vagrant up attempt ${attempt}/${attempts} in ${workdir}"

  if VAGRANT_DISABLE_VBOXSYMLINKCREATE=1 vagrant up --provider="$provider" 2>&1 | tee "$log_file"; then
    echo "Vagrant boot succeeded on attempt ${attempt}/${attempts}"
    exit 0
  fi

  echo "Vagrant boot failed on attempt ${attempt}/${attempts}. Log: ${log_file}"
  print_diagnostics

  if [[ "$attempt" -lt "$attempts" ]]; then
    cleanup_failed_attempt
    echo "Retrying after ${retry_delay}s..."
    sleep "$retry_delay"
  fi
done

echo "Vagrant boot failed after ${attempts} attempts."
exit 1
