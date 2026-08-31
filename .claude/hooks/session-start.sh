#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# This repo ships two deployment paths (Bash scripts + Ansible playbook) for
# provisioning real Ubuntu VMs; it has no app runtime dependencies to install.
# What CAN run inside this container is the static validation that CI also
# runs: ShellCheck against the root-level scripts, and an Ansible syntax
# check against ansible/playbook.yml. Full Vagrant-based integration tests
# require nested virtualization and are not runnable here.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

sudo apt-get update -qq
sudo apt-get install -y -qq shellcheck ansible >/dev/null

# Some harness shells hand child processes non-blocking stdio, which Ansible
# refuses to run under. Clear O_NONBLOCK on fd 0/1/2 before invoking it.
clear_nonblocking_stdio() {
  python3 - <<'PY'
import fcntl, os
for fd in (0, 1, 2):
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    except OSError:
        pass
PY
}
clear_nonblocking_stdio

# The apt "ansible" package's C-extension deps (e.g. cryptography's cffi
# backend) are built against the distro's default python3 (3.12 on Ubuntu
# 24.04), but this image's `python3` on PATH resolves to 3.11. Invoking
# ansible under python3.11 crashes on import with a PyO3 panic, so pin the
# interpreter explicitly here.
/usr/bin/python3.12 /usr/bin/ansible-galaxy collection install \
  -r "$CLAUDE_PROJECT_DIR/ansible/collections/requirements.yml"

if [ ! -f "$CLAUDE_PROJECT_DIR/ansible/inventory.ini" ]; then
  cp "$CLAUDE_PROJECT_DIR/ansible/inventory.ini.example" "$CLAUDE_PROJECT_DIR/ansible/inventory.ini"
fi
