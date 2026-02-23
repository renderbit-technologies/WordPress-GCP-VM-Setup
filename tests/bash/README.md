# Bash Script Testing Harness

This directory contains a Vagrant environment for testing the bash installation scripts (`setup-swap.sh`, `setup-wp-nginx.sh`).

## Prerequisites

- VirtualBox
- Vagrant

## Running Tests Locally

1. Navigate to this directory:
   ```bash
   cd tests/bash
   ```

2. Start the Vagrant environment:
   ```bash
   vagrant up
   ```
   This will automatically provision the VM using the scripts.

3. Verify the installation:
   The provisioner runs verification steps automatically. If the `vagrant up` command completes successfully, the tests passed.

4. To test idempotency (re-running scripts):
   ```bash
   vagrant provision
   ```

5. Access the VM manually:
   ```bash
   vagrant ssh
   ```

6. Cleanup:
   ```bash
   vagrant destroy -f
   ```

## Configuration

The `Vagrantfile` sets environment variables to run the scripts in non-interactive mode. It mounts the project root to `/vagrant` inside the VM.

### Environment Variables

The following environment variables control script behaviour during provisioning. All values in the `Vagrantfile` are **test-only credentials** and must never be used in production.

| Variable | Description | Default (in Vagrantfile) |
|---|---|---|
| `MYSQL_ROOT_PASS` | MySQL root password | `secure_root_password` |
| `WP_DB` | WordPress database name | `wp_test` |
| `WP_DB_USER` | WordPress database user | `wp_user` |
| `WP_DB_PASS` | WordPress database password | `secure_wp_password` |
| `WP_ADMIN_PASS` | WordPress admin password | `secure_admin_password` |
| `DOMAIN` | Server domain name | `vagrant.local` |
| `LE_EMAIL` | Email for Let's Encrypt | `admin@vagrant.local` |
| `USE_WWW` | Redirect to www subdomain (`y`/`n`) | `n` |
| `ENABLE_FAIL2BAN` | Enable Fail2Ban (`y`/`n`) | `y` |
| `CONT` | Auto-confirm prompts (`y`/`n`) | `y` |
| `SWAP_SIZE` | Swap file size | `1G` |

To customise these values for a local test run, export them before calling `vagrant up`:

```bash
export MYSQL_ROOT_PASS="my_root_pass"
vagrant up
```
