# GEMINI.md stale nginx/PHP source doc fix

## Background

Ondřej Surý deprecated his `ppa:ondrej/nginx` repository (announced 2026-01-19,
final packages pulled late April 2026), directing users to the official
nginx.org apt repository as the replacement. `ppa:ondrej/php` is unaffected
and remains active.

Investigation of this repository found the deployment code was never at risk:
`setup-wp-nginx.sh` and `ansible/roles/wordpress/tasks/main.yml` have always
installed nginx from the official nginx.org apt repo (keyring + pinning), and
only use `ppa:ondrej/php` for PHP. `README.md`, `CLAUDE.md`, and
`ansible/README.md` already describe this accurately.

`GEMINI.md`, however, still says:

- Line 7: `**Web Server:** Nginx (Ondrej PPA)` — inaccurate; was already wrong
  before the PPA deprecation, and now doubly misleading given the PPA no
  longer exists.
- Line 8: `**PHP:** 8.3 FPM ...` — stale; the stack has been on PHP 8.4 since
  before this task (see `CLAUDE.md`, `setup-wp-nginx.sh`).

## Scope

Documentation-only correction to `GEMINI.md`. No functional changes to
`setup-wp-nginx.sh` or the Ansible playbook are required, since neither ever
depended on the deprecated `ppa:ondrej/nginx`.

## Change

In `GEMINI.md`:

- `- **Web Server:** Nginx (Ondrej PPA)` → `- **Web Server:** Nginx (official nginx.org repo)`
  (matches phrasing already used in `README.md`, `CLAUDE.md`, `ansible/README.md`)
- `- **PHP:** 8.3 FPM (tuned to available CPU cores with OPcache enabled)` →
  `- **PHP:** 8.4 FPM (tuned to available CPU cores with OPcache enabled)`

## Out of scope

- No changes to `setup-wp-nginx.sh`, Ansible tasks/templates, or CI workflows.
- No other doc files touched — `README.md`, `CLAUDE.md`, `ansible/README.md`
  already state the correct nginx source.
