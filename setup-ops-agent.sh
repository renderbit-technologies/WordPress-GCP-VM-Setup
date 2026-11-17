#!/usr/bin/env bash
set -euo pipefail

# setup-ops-agent.sh
# Install the Google Cloud Ops Agent for log collection, with metrics turned
# off. Ops Agent metrics (agent.googleapis.com/*) are billed per MiB once the
# billing account's 150 MiB/month free tier is used up, and a single VM with
# the default metrics sends ~120 MiB/month. Compute Engine's own VM metrics
# (CPU, disk and network I/O) stay available in Cloud Monitoring for free.
# Supported targets: Ubuntu 24.04 LTS (noble) and Ubuntu 26.04 LTS (resolute)
#
# Supported Environment Variables:
#   ENABLE_OPS_AGENT  (Optional) auto/y/n. "auto" installs only when the GCE
#                     metadata server answers, i.e. on a GCP VM. [default: auto]

# -------------------------
# Formatting & Logging Helper Functions
# -------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
	echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
	echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
	echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
	echo -e "${RED}[ERROR]${NC} $1"
}

# Error Handler Trap
error_handler() {
	local line_no=$1
	log_error "Script failed at line $line_no."
	exit 1
}
trap 'error_handler ${LINENO}' ERR

# -------------------------
# Root Check
# -------------------------
if [ "$(id -u)" -ne 0 ]; then
	log_error "Please run as root: sudo $0"
	exit 1
fi

OPS_AGENT_CONFIG=/etc/google-cloud-ops-agent/config.yaml
ENABLE_OPS_AGENT=${ENABLE_OPS_AGENT:-auto}

echo "-------------------------------------------------------"
log_info "Starting Google Cloud Ops Agent Configuration..."
echo "-------------------------------------------------------"

is_gce() {
	curl -fsS -m 3 -H "Metadata-Flavor: Google" \
		"http://metadata.google.internal/computeMetadata/v1/instance/id" >/dev/null 2>&1
}

case "$ENABLE_OPS_AGENT" in
[Nn]*)
	log_info "ENABLE_OPS_AGENT=n. Skipping Ops Agent."
	exit 0
	;;
[Yy]*) ;;
*)
	if ! is_gce; then
		log_info "Not running on a GCP VM (no metadata server). Skipping Ops Agent."
		exit 0
	fi
	;;
esac

# 1. Install the agent. A failure here should not fail the whole WordPress
#    install, so it is reported and the script stops without an error.
if dpkg -s google-cloud-ops-agent >/dev/null 2>&1; then
	log_info "Ops Agent is already installed."
else
	log_info "Installing Ops Agent from Google's package repository..."
	TMPDIR=$(mktemp -d)
	trap 'rm -rf "$TMPDIR"' EXIT
	if curl -fsSL "https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh" \
		-o "$TMPDIR/add-google-cloud-ops-agent-repo.sh" &&
		bash "$TMPDIR/add-google-cloud-ops-agent-repo.sh" --also-install; then
		log_success "Ops Agent installed."
	else
		log_warn "Ops Agent installation failed (this OS release may not be supported yet). Continuing without it."
		exit 0
	fi
fi

# 2. Logging stays at the agent's built-in defaults (syslog); metrics are off.
log_info "Writing $OPS_AGENT_CONFIG (logging on, metrics off)..."
NEW_CONFIG=$(mktemp)
cat >"$NEW_CONFIG" <<'YAML'
# Managed by WordPress-GCP-VM-Setup.
# Logging: Ops Agent built-in defaults (syslog).
# Metrics: disabled. Ops Agent metrics are billed per MiB beyond the billing
# account's 150 MiB/month free tier; Compute Engine's own VM metrics (CPU,
# disk and network I/O) remain available in Cloud Monitoring at no cost.
metrics:
  service:
    pipelines:
      default_pipeline:
        receivers: []
YAML

if [ -f "$OPS_AGENT_CONFIG" ] && cmp -s "$NEW_CONFIG" "$OPS_AGENT_CONFIG"; then
	rm -f "$NEW_CONFIG"
	log_info "Ops Agent config is already up to date."
else
	if [ -f "$OPS_AGENT_CONFIG" ]; then
		cp -p "$OPS_AGENT_CONFIG" "$OPS_AGENT_CONFIG.bak-$(date +%Y%m%d-%H%M%S)"
	fi
	install -m 0644 -o root -g root "$NEW_CONFIG" "$OPS_AGENT_CONFIG"
	rm -f "$NEW_CONFIG"
	systemctl restart google-cloud-ops-agent
	log_success "Ops Agent config updated and agent restarted."
fi

systemctl enable google-cloud-ops-agent >/dev/null 2>&1 || true
log_success "Ops Agent setup complete (logging on, metrics off)."
