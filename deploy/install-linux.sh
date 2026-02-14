#!/bin/bash
# ──────────────────────────────────────────────────────────────
# Raypher Linux Install Script
# Installs the Raypher binary and enables the systemd service.
# ──────────────────────────────────────────────────────────────

set -e

INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/raypher.service"
DATA_DIR="/var/lib/raypher"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════╗"
echo "║   RAYPHER — Linux Installer          ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo $0"
    exit 1
fi

# Copy binary
echo "📦 Installing binary to ${INSTALL_DIR}/raypher..."
cp "${SCRIPT_DIR}/../target/release/raypher-core" "${INSTALL_DIR}/raypher"
chmod +x "${INSTALL_DIR}/raypher"

# Create data directory
echo "📁 Creating data directory at ${DATA_DIR}..."
mkdir -p "${DATA_DIR}"

# Install systemd service
echo "⚙️  Installing systemd service..."
cp "${SCRIPT_DIR}/raypher.service" "${SERVICE_FILE}"
systemctl daemon-reload
systemctl enable raypher.service

echo ""
echo "✅ Raypher installed successfully!"
echo ""
echo "Commands:"
echo "  sudo systemctl start raypher    — Start the service"
echo "  sudo systemctl status raypher   — Check status"
echo "  sudo systemctl stop raypher     — Stop the service"
echo "  journalctl -u raypher -f        — View live logs"
echo ""
