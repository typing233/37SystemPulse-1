#!/bin/bash
set -euo pipefail

VERSION="0.1.0"
PROJECT="syspulse"
RELEASE_DIR="release"

echo "=== Building ${PROJECT} v${VERSION} ==="

# Clean
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

# Run tests
echo "[1/4] Running tests..."
cargo test --quiet
echo "  ✓ All tests passed"

# Build static binary (Linux x86_64)
echo "[2/4] Building static binary (x86_64-linux-musl)..."
cargo build --release --target x86_64-unknown-linux-musl
cp "target/x86_64-unknown-linux-musl/release/${PROJECT}" "${RELEASE_DIR}/${PROJECT}-linux-amd64"
echo "  ✓ Binary: ${RELEASE_DIR}/${PROJECT}-linux-amd64 ($(du -h "${RELEASE_DIR}/${PROJECT}-linux-amd64" | cut -f1))"

# Build native (dynamic) for benchmarking
echo "[3/4] Building native release..."
cargo build --release
cp "target/release/${PROJECT}" "${RELEASE_DIR}/${PROJECT}-linux-amd64-native"
echo "  ✓ Binary: ${RELEASE_DIR}/${PROJECT}-linux-amd64-native ($(du -h "${RELEASE_DIR}/${PROJECT}-linux-amd64-native" | cut -f1))"

# Package
echo "[4/4] Packaging..."
cd "${RELEASE_DIR}"
sha256sum * > SHA256SUMS
cd ..

echo ""
echo "=== Release artifacts ==="
ls -lh "${RELEASE_DIR}/"
echo ""
echo "=== Verification ==="
file "${RELEASE_DIR}/${PROJECT}-linux-amd64"
ldd "${RELEASE_DIR}/${PROJECT}-linux-amd64" 2>&1 || true
echo ""
echo "Done. Static binary ready for deployment."
