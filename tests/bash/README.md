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
