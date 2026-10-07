#!/usr/bin/env bash

set -euo pipefail

workdir="${1:?usage: run-vagrant-up-with-retry.sh <workdir> [provider]}"
provider="${2:-virtualbox}"
attempts="${VAGRANT_UP_ATTEMPTS:-2}"
retry_delay="${VAGRANT_UP_RETRY_DELAY_SECONDS:-30}"
# Caps each attempt so a stall after boot (e.g. apt hanging inside the
# provisioner) is retried instead of running until the job is cancelled.
attempt_timeout="${VAGRANT_UP_ATTEMPT_TIMEOUT_SECONDS:-1200}"

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

  # No --foreground: timeout must signal vagrant's whole process group so its
  # ssh children exit too and tee sees EOF.
  rc=0
  VAGRANT_DISABLE_VBOXSYMLINKCREATE=1 timeout --kill-after=60 "$attempt_timeout" \
    vagrant up --provider="$provider" 2>&1 | tee "$log_file" || rc=$?

  if [[ "$rc" -eq 0 ]]; then
    echo "Vagrant boot succeeded on attempt ${attempt}/${attempts}"
    exit 0
  fi

  if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
    echo "Vagrant up hung on attempt ${attempt}/${attempts}; timed out after ${attempt_timeout}s. Log: ${log_file}"
  else
    echo "Vagrant boot failed on attempt ${attempt}/${attempts} (exit ${rc}). Log: ${log_file}"
  fi
  print_diagnostics

  if [[ "$attempt" -lt "$attempts" ]]; then
    cleanup_failed_attempt
    echo "Retrying after ${retry_delay}s..."
    sleep "$retry_delay"
  fi
done

echo "Vagrant boot failed after ${attempts} attempts."
exit 1
