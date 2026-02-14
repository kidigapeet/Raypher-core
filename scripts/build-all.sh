#!/bin/bash
# Raypher Core — Multi-Platform Build Script
# Builds release binaries for all supported targets

set -euo pipefail

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
DIST_DIR="dist/v${VERSION}"
mkdir -p "$DIST_DIR"

echo "🔨 Building Raypher Core v${VERSION}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Target 1: Linux x86_64 (primary)
echo "📦 Building for Linux x86_64..."
cross build --target x86_64-unknown-linux-gnu --release --no-default-features
cp target/x86_64-unknown-linux-gnu/release/raypher-core "$DIST_DIR/raypher-core-linux-amd64"
echo "   ✅ $(du -h "$DIST_DIR/raypher-core-linux-amd64" | cut -f1)"

# Target 2: Windows x86_64
echo "📦 Building for Windows x86_64..."
cross build --target x86_64-pc-windows-gnu --release
cp target/x86_64-pc-windows-gnu/release/raypher-core.exe "$DIST_DIR/raypher-core-windows-amd64.exe"
echo "   ✅ $(du -h "$DIST_DIR/raypher-core-windows-amd64.exe" | cut -f1)"

# Target 3: Linux ARM64 (Raspberry Pi / AWS Graviton)
echo "📦 Building for Linux ARM64..."
cross build --target aarch64-unknown-linux-gnu --release --no-default-features
cp target/aarch64-unknown-linux-gnu/release/raypher-core "$DIST_DIR/raypher-core-linux-arm64"
echo "   ✅ $(du -h "$DIST_DIR/raypher-core-linux-arm64" | cut -f1)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ All builds complete!"
echo ""
ls -lh "$DIST_DIR/"
echo ""

# Generate SHA-256 checksums for verification
cd "$DIST_DIR"
sha256sum * > checksums.sha256
echo "📋 Checksums generated:"
cat checksums.sha256
