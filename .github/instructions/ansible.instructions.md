---
description: "Use when editing Ansible playbooks, roles, handlers, templates, inventory, or Vagrant-based Ansible tests under ansible/**. Covers playbook-specific editing rules, inventory safety, and the required validation flow."
applyTo: "ansible/**"
---

# Ansible Guidelines

- Treat `ansible/playbook.yml` as the Ansible entrypoint and preserve the role order: `common` -> `swap` -> `wordpress` -> `security`.
- Keep Ansible behavior aligned with the root-level Bash scripts when a change affects shared deployment behavior, unless the task is explicitly Ansible-only.
- Prefer idempotent tasks. Re-runs must stay safe, especially for package install, swap creation, database setup, WordPress bootstrap, and certificate handling.
- Prefer `ansible.builtin.*` modules when available and keep task names specific enough to make play output readable.
- When a task handles generated credentials or secrets, preserve `no_log: true` and avoid exposing secrets in templates, debug output, or task results.
- Preserve existing variable names and interfaces from `ansible/playbook.yml` and `ansible/README.md`. Do not invent parallel names for behavior that already exists in the Bash path.
- When changing templates or config files that affect services, keep handlers and notifications in sync instead of relying on unconditional restarts.

# Inventory Safety

- Do not commit real hostnames, IPs, usernames, private keys, or passwords into `ansible/inventory.ini`.
- Treat `ansible/inventory.ini.example` as the safe template for documented inventory changes.
- If validation needs a local inventory file, follow CI: copy `inventory.ini.example` to `inventory.ini` locally rather than editing tracked inventory with machine-specific values.
- Keep Vagrant and test-only values clearly separate from production guidance.

# Validation Flow

- For Ansible changes, run the same flow the repository uses in CI when the environment allows it.
- Syntax check:

  ```bash
  cd ansible
  cp inventory.ini.example inventory.ini
  ansible-galaxy collection install community.mysql
  ansible-playbook playbook.yml --syntax-check
  ```

- Full local validation:

  ```bash
  cd ansible
  vagrant up
  vagrant ssh -c "curl -I http://localhost"
  vagrant provision
  vagrant ssh -c "curl -I http://localhost"
  ```

- For local and CI-style testing without public DNS, keep SSL disabled through the documented Ansible path such as `enable_ssl=false`.

# Key References

- See `ansible/README.md` for variables, Vagrant workflow, and role behavior.
- See `.github/workflows/ansible-test.yml` for the CI validation sequence.
- See `.github/copilot-instructions.md` for repository-wide rules that still apply alongside this file.
