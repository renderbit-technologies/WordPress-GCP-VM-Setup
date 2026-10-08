#!/usr/bin/env bash

set -euo pipefail

workdir="${1:?usage: run-vagrant-up-with-retry.sh <workdir> [provider]}"
provider="${2:-virtualbox}"
attempts="${VAGRANT_UP_ATTEMPTS:-2}"
retry_delay="${VAGRANT_UP_RETRY_DELAY_SECONDS:-30}"
# Caps each attempt so a stall after boot (e.g. apt hanging inside the
# provisioner) is retried instead of running until the job is cancelled.
attempt_timeout="${VAGRANT_UP_ATTEMPT_TIMEOUT_SECONDS:-1800}"
# How often the background monitor writes a one-line host resource summary
# into the step log, so a starved runner leaves a trail; 0 disables it.
monitor_interval="${VAGRANT_UP_MONITOR_INTERVAL_SECONDS:-60}"

cd "$workdir"

host_summary() {
  local load mem swap
  load="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo '?')"
  mem="$(free -m 2>/dev/null | awk '/^Mem:/ {print $3 " used/" $7 " avail"}')"
  swap="$(free -m 2>/dev/null | awk '/^Swap:/ {print $3 " used"}')"
  echo "[host $(date -u +%H:%M:%S)] load ${load} | mem MiB ${mem:-?} | swap MiB ${swap:-?} | VBoxHeadless $(pgrep -c -x VBoxHeadless || true)"
}

print_host_resources() {
  echo "::group::Host resources"
  uptime || true
  free -m || true
  ps -eo pid,ppid,pgid,stat,etimes,pcpu,rss,comm --sort=-pcpu | head -15 || true
  pgrep -a 'VBox|vagrant|ssh' || true
  echo "::endgroup::"
}

start_resource_monitor() {
  [[ "$monitor_interval" -gt 0 ]] || return 0
  (
    sleep_pid=""
    # Kill the pending sleep too, so it can't hold the step's stdout open
    # after the script exits.
    trap 'kill "$sleep_pid" 2>/dev/null; exit 0' TERM
    while true; do
      host_summary
      sleep "$monitor_interval" &
      sleep_pid=$!
      wait "$sleep_pid"
    done
  ) &
  monitor_pid=$!
  trap 'kill "$monitor_pid" 2>/dev/null || true' EXIT
}

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
  print_host_resources
}

# True once no VM is running: VirtualBox lists none and no VBoxHeadless
# (VM) process is left.
vms_stopped() {
  if command -v VBoxManage >/dev/null 2>&1 &&
    [[ -n "$(VBoxManage list runningvms 2>/dev/null)" ]]; then
    return 1
  fi
  ! pgrep -x VBoxHeadless >/dev/null
}

wait_for_vms_stopped() {
  local deadline=$((SECONDS + $1))
  until vms_stopped; do
    if ((SECONDS >= deadline)); then
      return 1
    fi
    sleep 2
  done
}

# Returns non-zero if a VM is still running afterwards; the caller must not
# boot another one next to it.
cleanup_failed_attempt() {
  local vm_id rc=0
  echo "::group::Cleaning up failed Vagrant attempt"
  vm_id="$(cat .vagrant/machines/default/virtualbox/id 2>/dev/null || true)"

  # After a timed-out attempt, vagrant halt -f/destroy -f are not guaranteed
  # to stop the VM, so power it off through VirtualBox directly first.
  if [[ -n "$vm_id" ]] && command -v VBoxManage >/dev/null 2>&1; then
    VBoxManage controlvm "$vm_id" poweroff || true
  fi
  vagrant halt -f || true
  vagrant destroy -f || true

  if ! wait_for_vms_stopped 60; then
    if [[ -n "$vm_id" ]] && command -v VBoxManage >/dev/null 2>&1; then
      VBoxManage unregistervm "$vm_id" --delete || true
    fi
    wait_for_vms_stopped 30 || rc=1
  fi

  if command -v VBoxManage >/dev/null 2>&1; then
    VBoxManage list runningvms || true
  fi

  echo "::endgroup::"
  print_host_resources
  return "$rc"
}

start_resource_monitor

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
    if ! cleanup_failed_attempt; then
      # A second 2-vCPU VM booting next to a leftover one can starve the runner
      # until GitHub drops it ("lost communication") and the log is lost; a
      # failed step keeps its log.
      echo "::error::A VirtualBox VM is still running after cleanup; not retrying."
      exit 1
    fi
    echo "Retrying after ${retry_delay}s..."
    sleep "$retry_delay"
  fi
done

echo "Vagrant boot failed after ${attempts} attempts."
exit 1
