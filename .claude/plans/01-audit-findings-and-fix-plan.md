# WordPress-GCP-VM-Setup — Audit Findings & Fix Plan

## Context

Full audit of both deployment paths (Bash scripts + Ansible playbook), the nginx/PHP/MariaDB configuration they produce, the Vagrant/runner test harnesses, and the CI workflows. Goal: identify logic bugs, silent failures, security/robustness issues, test coverage gaps, and optimization opportunities, then fix them in priority order. Per CLAUDE.md, every shared-behavior fix must land in **both** paths.

Severity legend: **[C]** breaks production or data, **[M]** wrong/fragile behavior, **[L]** cleanup/optimization.

---

## Findings

### A. Critical correctness bugs

- **A1 [C] Ansible re-run breaks the live site's DB auth.** Blank `vars_prompt` answers regenerate `wp_db_pass` ([playbook.yml:35-51](ansible/playbook.yml)); `mysql_user` then updates the DB user's password (`update_password: always` default, [wordpress/tasks/main.yml:241-248](ansible/roles/wordpress/tasks/main.yml)) while `wp config create` is skipped by its `creates:` guard — wp-config keeps the old password → "Error establishing a database connection". Same for `mysql_root_pass` (root password silently rotated) and `/root/.wp-credentials` overwritten with the new values. CI never catches this because Vagrant passes fixed `wp_db_pass: vagrant` via extra_vars.
  **Fix:** mirror the Bash credential-reuse behavior — pre_task that stats/slurps `/root/.wp-credentials` and reuses parsed passwords when prompts are blank; only generate when no prior file. Additionally set `update_password: on_create` as a safety net for the WP DB user.

- **A2 [C] Ansible re-run silently reverts certbot's HTTPS config.** Certbot edits `sites-available/{{ domain }}` in place on first run. On re-run, the template task ([wordpress/tasks/main.yml:359-366](ansible/roles/wordpress/tasks/main.yml)) sees drift and rewrites the HTTP-only config, while the certbot task is skipped by `creates: /etc/letsencrypt/live/{{ domain }}/fullchain.pem` ([:559-566]) — HTTPS server block gone, site downgraded to HTTP until manual intervention. Hidden in CI because tests run `enable_ssl: false`.
  **Fix:** render the TLS-aware config ourselves. Template gains a conditional 443 block using `/etc/letsencrypt/live/{{ domain }}/` paths, gated on a `stat` of the cert; run certbot with `certonly --nginx`-style non-destructive mode (or keep `--nginx` but drop the template overwrite once certs exist). Simplest robust shape: check cert existence first, template accordingly, notify reload.

- **A3 [C] Bash re-run has the same certbot-revert window.** [setup-wp-nginx.sh:332](setup-wp-nginx.sh) unconditionally rewrites the site config, then relies on certbot at the end to restore HTTPS. If certbot fails on the re-run (rate limits, transient DNS), the site is left HTTP-only; with `SKIP_CERTBOT=y` on a host that previously had certs, HTTPS is dropped unconditionally.
  **Fix:** same strategy as A2 — detect existing cert (`/etc/letsencrypt/live/$DOMAIN/fullchain.pem`) and emit the HTTPS server block directly, so the config is correct regardless of certbot outcome.

- **A4 [C] Uploads over 1 MB fail — `client_max_body_size` is never set.** PHP is tuned to `upload_max_filesize=64M`/`post_max_size=64M`, but nginx's default 1M body limit makes that dead config; media uploads return HTTP 413. Affects the heredoc in [setup-wp-nginx.sh:332-411](setup-wp-nginx.sh) and [nginx-site.conf.j2](ansible/roles/wordpress/templates/nginx-site.conf.j2).
  **Fix:** add `client_max_body_size 64m;` to the server block in both paths.

- **A5 [C] Fresh installs have no theme — blank front page.** Both paths run `wp core download --skip-content` ([setup-wp-nginx.sh:476](setup-wp-nginx.sh), [wordpress/tasks/main.yml:392](ansible/roles/wordpress/tasks/main.yml)) and never install any theme. WP installs fine and wp-login works, but the public site renders nothing. Tests only assert HTTP 200/301, so this passes CI.
  **Fix:** after core install, `wp theme install twentytwentyfive --activate` guarded by "no theme currently active" (idempotent, doesn't stomp a user-chosen theme on re-runs). Both paths.

- **A6 [C] Critical steps can fail silently.** Ansible: `wp core install` has `failed_when: false` **and** `changed_when: false` ([wordpress/tasks/main.yml:412-426](ansible/roles/wordpress/tasks/main.yml)) — a failed install (bad DB creds, DB down) produces a green play. Same masking on plugin install (:507-526), root password set (:265-271), certbot (:559-574). Bash: `wp core download ... || true` ([setup-wp-nginx.sh:476](setup-wp-nginx.sh)) masks download failure, then `config create` fails confusingly later; cred-file parsing ([:151-153]) can yield empty strings (corrupt/foreign file) which then flow into `ALTER USER ... IDENTIFIED BY ''`.
  **Fix:** remove `failed_when: false` from core install / DB tasks (keep it only where failure is genuinely acceptable, with a comment saying why); in Bash, drop `|| true` from core download and validate parsed credentials are non-empty before use, aborting with a clear message otherwise.

### B. Medium bugs & divergences between paths

- **B1 [M] Broken sed makes realpath-cache tuning a no-op (Bash only).** `sed -i "s/^;?realpath_cache_size = .*/…/"` ([setup-wp-nginx.sh:240-241](setup-wp-nginx.sh)) — POSIX BRE treats `;?` literally, so neither line ever matches. Ansible's `lineinfile` regexp `^;?…` works ([wordpress/tasks/main.yml:120-132](ansible/roles/wordpress/tasks/main.yml)), so the two paths silently diverge.
  **Fix:** use `sed -E -i "s/^;?realpath_cache_size…"` (and same for `realpath_cache_ttl`), or append-if-missing like the other keys.

- **B2 [M] Plugin auto-updates enabled before plugins exist (Bash only).** `wp plugin auto-updates enable --all` runs at [setup-wp-nginx.sh:601](setup-wp-nginx.sh) *before* the plugin install at [:608] — with `--skip-content` there are zero plugins at that point, so the "essential plugins" never get auto-updates. Ansible has the correct order.
  **Fix:** move the auto-updates block after plugin install.

- **B3 [M] phpMyAdmin blowfish secret can corrupt config.inc.php (Ansible).** `lookup('password', … chars=ascii_letters,digits,special)` ([playbook.yml:53-56](ansible/playbook.yml)) can emit `'` or `\`, which breaks the single-quoted PHP string injected by `replace` ([wordpress/tasks/main.yml:193-197](ansible/roles/wordpress/tasks/main.yml)) — intermittent PMA hard-failure.
  **Fix:** `chars=ascii_letters,digits`, keep `length=32`.

- **B4 [M] Bash blowfish secret is 44 chars, not 32.** `openssl rand -base64 32` → 44 chars ([setup-wp-nginx.sh:146](setup-wp-nginx.sh)); phpMyAdmin expects exactly 32 bytes (warns/complains on mismatch).
  **Fix:** generate exactly 32 chars (e.g. `openssl rand -base64 24` = 32 chars, or `openssl rand -hex 16`).

- **B5 [M] Bash reinstalls phpMyAdmin from "latest" on every run.** `rm -rf $PMA_ROOT` + unpinned download ([setup-wp-nginx.sh:271-276](setup-wp-nginx.sh)): non-idempotent, rotates the blowfish secret every run (kills PMA sessions), no checksum, upstream "latest" changes can break re-runs. Ansible correctly skips when installed but shares the unpinned/no-checksum download.
  **Fix:** Bash: skip when `$PMA_ROOT/index.php` exists (align with Ansible). Both: pin a PMA version and verify sha256; preserve existing config.inc.php/blowfish across runs.

- **B6 [M] Anonymous-user "hardening" is a silent no-op on MariaDB 10.11.** `DELETE FROM mysql.user …` fails (view, not table) and is masked by `|| true` ([setup-wp-nginx.sh:438](setup-wp-nginx.sh)).
  **Fix:** `DROP USER IF EXISTS ''@'localhost';` (and `''@'{{ hostname }}'`). Ansible's `mysql_user` approach is fine.

- **B7 [M] Site URL stays `http://` forever.** Both paths install with `--url=http://$DOMAIN` and never update `home`/`siteurl` after certbot succeeds → permanent extra 301s on every asset, scheme confusion with `FORCE_SSL_ADMIN`.
  **Fix:** on certbot success, `wp option update home/siteurl https://$DOMAIN` (both paths, guarded so SKIP_CERTBOT/enable_ssl=false keeps http).

- **B8 [M] install.sh clobbers and deletes local repo files.** It downloads `setup-*.sh` from GitHub `main` into the CWD and `rm`s them afterwards ([install.sh:22-40](install.sh)). Run from a clone, it overwrites the tracked scripts with remote versions (ignoring local changes) and then deletes them from the working tree.
  **Fix:** work in `mktemp -d`; if `setup-swap.sh`/`setup-wp-nginx.sh` exist next to install.sh, use the local copies instead of downloading.

- **B9 [M] Swap role can't repair a half-finished setup (Ansible).** `mkswap`/`swapon` are gated on the *pre-run* stat of `/swapfile` ([swap/tasks/main.yml:20-28](ansible/roles/swap/tasks/main.yml)) — if a prior run created the file but died before mkswap/swapon, every future run skips both forever. Bash checks actual state (`file`, `swapon --show`) and is correct.
  **Fix:** replace the `when: not swap_file_check…` guards with state checks (`command: file /swapfile` + grep for "swap file"; `swapon --show` grep) mirroring the Bash logic. Also remove the thinking-out-loud comment block (:29-33).

- **B10 [M] Unattended-upgrades parity gap.** Ansible writes `50unattended-upgrades` (security-only) + `20auto-upgrades` explicitly; Bash only runs `dpkg-reconfigure` ([setup-wp-nginx.sh:663-665](setup-wp-nginx.sh)) and relies on distro defaults. CLAUDE.md claims parity.
  **Fix:** Bash writes the same two files with identical content.

- **B11 [M] nginx.org `conf.d/default.conf` left active (both paths).** Requests with unmatched Host (e.g. bare IP) hit the stock nginx welcome page; it competes as the implicit default server.
  **Fix:** remove `/etc/nginx/conf.d/default.conf` in both paths (idempotently); optionally add an explicit catch-all `server { listen 80 default_server; return 444; }`.

- **B12 [M] Hidden-files block will break webroot-based ACME renewals.** `location ~ /\.` denies `/.well-known/acme-challenge/` (works today only because the certbot nginx plugin injects exact-match locations during authentication).
  **Fix:** exempt `.well-known` — e.g. an explicit `location ^~ /.well-known/acme-challenge/ { allow all; }` above the deny (both paths).

- **B13 [M] Secrets on process argv / in logs.** `mysql -p"$PASS"`, `wp core install --admin_password=…` expose passwords in `/proc` during runs; the final Bash block and the Ansible `debug` task print all passwords to stdout (persisted in CI logs).
  **Fix:** use `MYSQL_PWD` env or `--defaults-extra-file` for mysql; keep wp-cli as-is (local root-only VM, acceptable) but stop echoing credentials when non-interactive (`[ -t 1 ]` guard in Bash; drop/`no_log` the Ansible debug task or gate behind a `show_credentials` var).

- **B14 [M] No input validation.** `DOMAIN`, `WP_DB`, `WP_DB_USER` are interpolated into SQL, file paths, and nginx config unquoted/unescaped in Bash.
  **Fix:** validate at entry (`[[ "$DOMAIN" =~ ^[a-z0-9.-]+$ ]]`, `[[ "$WP_DB" =~ ^[A-Za-z0-9_]+$ ]]` etc.), abort with a clear error.

- **B15 [M] Unpinned, unverified downloads.** wp-cli.phar (both), phpMyAdmin zip (both), nginx signing key (fetch-and-trust). Supply-chain and repeatability risk.
  **Fix:** pin wp-cli release URL + sha512 check (wp-cli publishes checksums); pin PMA version + sha256; keep nginx key fetch but this is lower risk (verified by apt afterwards).

### C. Test coverage gaps

- **C1 [C-gap] Ansible harness asserts nothing.** [ansible/Vagrantfile](ansible/Vagrantfile) has no verify step; the workflow's `vagrant ssh -c "curl -I http://localhost"` ([ansible-test.yml](.github/workflows/ansible-test.yml)) exits 0 for *any* HTTP response (even 500) and sends no `Host:` header, so it hits the default server, not the WordPress vhost. Combined with the `failed_when: false` masking (A6), the Ansible pipeline can be fully green with a dead site.
- **C2 [C-gap] Idempotency tests are rigged to miss the credential bugs.** Both harnesses pass fixed passwords, so the A1 regeneration bug and Bash cred-file parse path with generated passwords are never exercised.
- **C3 [M-gap] No behavior assertions.** Nothing tests: wp-login.php 200, front page contains WordPress markup (would have caught A5), `/phpmyadmin` 200, `xmlrpc.php` → 403, `wp-config.php` → 403, hidden files → 403, PHP-in-uploads → 403, upload >1M (would have caught A4), swap active after provision, cred file exists with mode 600.
- **C4 [M-gap] install.sh is never tested** (harnesses invoke setup-*.sh directly), so its download/orchestration logic has zero coverage.
- **C5 [L-gap] tests/bash/Vagrantfile doesn't set SKIP_CERTBOT** — certbot runs, fails against `vagrant.local`, and the failure path is silently tolerated; wastes CI time and contradicts CLAUDE.md's description.
- **C6 [L-gap] No ansible-lint/yamllint in CI** (only ShellCheck + Trivy). ansible-test has no scheduled run (bash-test runs nightly), so "latest"-download breakage is only detected on the bash side.

**Fix (one coherent change):** create a shared verification script `tests/verify-deployment.sh` (status-code + content assertions listed in C3, parametrized by DOMAIN/creds) and call it from: tests/bash/Vagrantfile provisioner, run-on-runner.sh, a new verify provisioner/step in ansible/Vagrantfile + ansible-test.yml (with proper Host header and `curl -f`). Add a second idempotency scenario without pre-set passwords (asserts site still up and creds file consistent after re-provision). Add ansible-lint job and a nightly schedule to ansible-test.yml. Set `SKIP_CERTBOT=y` in tests/bash/Vagrantfile.

### D. Optimizations & cleanup

- **D1 [L] No gzip.** nginx.org default has gzip mostly off — add a gzip snippet (text/css/js/svg/json, `gzip_vary on`) in both paths. Biggest cheap perf win for a WP site.
- **D2 [L] FPM sizing ignores RAM.** `max_children = cores × 5` with `memory_limit=256M` can theoretically commit ~2.5G on a 2-core/2GB VM alongside MariaDB. Cap children by available RAM (e.g. `min(cores*5, (RAM_MB-768)/96)`), or at minimum document the assumption. Apply same formula both paths.
- **D3 [L] Obsolete `opcache.fast_shutdown=1`** (removed in PHP 7.2) in [opcache.ini.j2](ansible/roles/wordpress/templates/opcache.ini.j2) and the Bash heredoc — drop it.
- **D4 [L] `find … -exec chmod {} \;`** in Bash spawns one process per file ([setup-wp-nginx.sh:565-566,697-698](setup-wp-nginx.sh)) — use `+` (Ansible security role already does).
- **D5 [L] WP-CLI cache misses:** `sudo -u www-data` keeps `HOME=/root` → wp-cli cache unwritable, silent re-downloads. Use `sudo -H -u www-data` in Bash and cron template; Ansible `become_user` already handles HOME.
- **D6 [L] Static-asset regex** could include `webp|avif` (both paths).
- **D7 [L] Duplicate `include fastcgi_params`** in PHP locations (heredoc + snippet both include it) — harmless; tidy by removing the explicit one.
- **D8 [L] Redundant `apt-get update`** calls in Bash (add-apt-repository already refreshes) — minor CI-time saving.
- **D9 [L] Bash hardcodes `WP_ADMIN_USER="user"`** while Ansible exposes `wp_admin_user` — add `WP_ADMIN_USER` env support to Bash for parity.
- **D10 [L] `CRED_FILE="$HOME/.wp-credentials"`** — make it literal `/root/.wp-credentials` (docs promise that path; `$HOME` depends on sudo config).

### E. Documentation drift

- **E1** README.md:9, CLAUDE.md:12/126, ansible/README.md:32 say "Nginx (Ondrej PPA)" — code uses the official nginx.org repo. Correct the docs.
- **E2** CLAUDE.md tells contributors to install only `community.mysql`; the playbook also requires `ansible.posix` (swap role). Point docs at `ansible-galaxy collection install -r ansible/collections/requirements.yml`.
- **E3** Document the credential-reuse contract (what happens on re-runs) for both paths once A1 is fixed; note SKIP_CERTBOT behavior in the Vagrant harness (C5).

---

## Implementation plan (phased, each phase independently verifiable)

### Phase 1 — Critical correctness (A1–A6)
Files: `setup-wp-nginx.sh`, `ansible/playbook.yml`, `ansible/roles/wordpress/tasks/main.yml`, `ansible/roles/wordpress/templates/nginx-site.conf.j2`.
1. Add `client_max_body_size 64m;` (A4) — 2-line change, both configs.
2. Theme install-and-activate guarded step (A5), both paths.
3. Ansible credential reuse from `/root/.wp-credentials` + `update_password: on_create` (A1).
4. TLS-aware nginx config rendering keyed on existing cert (A2 bash+ansible, A3).
5. Un-mask critical failures; validate parsed credentials in Bash (A6).
   → verify: `cd tests/bash && vagrant up && vagrant provision`; `cd ansible && vagrant up && vagrant provision`.

### Phase 2 — Test hardening (C1–C6)
Files: new `tests/verify-deployment.sh`, `tests/bash/Vagrantfile`, `tests/bash/run-on-runner.sh`, `ansible/Vagrantfile`, `.github/workflows/ansible-test.yml`, `.github/workflows/bash-test.yml`, new ansible-lint workflow.
Do this immediately after Phase 1 so the new assertions lock in the fixes (upload-size test guards A4, content assertion guards A5, blank-password idempotency scenario guards A1).

### Phase 3 — Medium bugs & security robustness (B1–B15)
Files: `setup-wp-nginx.sh`, `install.sh`, `setup-swap.sh` (minor), ansible wordpress/swap/security roles + playbook.
Order within phase: B1, B2 (one-liners) → B6, B7, B10, B11, B12 (config correctness) → B3, B4, B5, B15 (PMA/downloads) → B8, B9 → B13, B14.

### Phase 4 — Optimizations, cleanup, docs (D1–D10, E1–E3)
Low-risk sweep; gzip (D1) and FPM sizing (D2) get test-run scrutiny, the rest are mechanical.

### Conventions for all phases
- Every shared-behavior change lands in **both** Bash and Ansible in the same commit (CLAUDE.md rule).
- Conventional Commits, one logical fix per commit (e.g. `fix(nginx): set client_max_body_size to match php upload limits`).
- ShellCheck clean after every Bash change (`shellcheck *.sh tests/bash/*.sh .github/scripts/*.sh`).
- `ansible-playbook playbook.yml --syntax-check` after every Ansible change.

## Verification (end-to-end)
1. `shellcheck` all scripts — clean.
2. `cd ansible && ansible-playbook playbook.yml --syntax-check` — clean.
3. Bash harness: `cd tests/bash && vagrant up` (initial) then `vagrant provision` (idempotency) — new verify script asserts: front page 200 **with WP content**, wp-login 200, `/phpmyadmin` reachable, xmlrpc/wp-config/hidden-files 403, >1MB upload accepted at nginx layer, swap active, creds file 0600 and consistent across runs.
4. Ansible harness: `cd ansible && vagrant up && vagrant provision` — same verify script via new provisioner step; second scenario with auto-generated (blank) passwords must survive re-provision.
5. CI: all four workflows green; new ansible-lint job green.

## Decisions made (flag if you disagree)
- Install/activate `twentytwentyfive` as default theme (A5) — behavior change for fresh installs; alternative is documenting "no theme by default", which leaves a blank production site.
- Kept the 12-plugin "essentials" list as-is (slimming it — wordfence + sucuri + jetpack-protect overlap — is opinionated product territory; flagged, not changed).
- phpMyAdmin stays publicly routed at `/phpmyadmin` (adding IP-allowlist/basic-auth is a scope change; noted as an optional hardening follow-up).
