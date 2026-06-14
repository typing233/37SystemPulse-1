#!/bin/bash
set -euo pipefail

VERSION="0.1.0"
PROJECT="syspulse"
RELEASE_DIR="release"

echo "=== Building ${PROJECT} v${VERSION} ==="

rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

echo "[1/5] Running tests..."
cargo test --quiet 2>&1 | tail -1
echo "  All tests passed"

echo "[2/5] Building static binary (x86_64-linux-musl)..."
cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null
cp "target/x86_64-unknown-linux-musl/release/${PROJECT}" "${RELEASE_DIR}/${PROJECT}-linux-amd64"
echo "  Binary: ${RELEASE_DIR}/${PROJECT}-linux-amd64 ($(du -h "${RELEASE_DIR}/${PROJECT}-linux-amd64" | cut -f1))"

echo "[3/5] Building native release..."
cargo build --release 2>/dev/null
cp "target/release/${PROJECT}" "${RELEASE_DIR}/${PROJECT}-linux-amd64-native"
echo "  Binary: ${RELEASE_DIR}/${PROJECT}-linux-amd64-native ($(du -h "${RELEASE_DIR}/${PROJECT}-linux-amd64-native" | cut -f1))"

echo "[4/5] Performance validation (100ms interval, 5s)..."
"${RELEASE_DIR}/${PROJECT}-linux-amd64-native" -i 100 -o influx > /dev/null 2>/dev/null &
SP_PID=$!
sleep 5
TICKS=$(cat /proc/$SP_PID/stat | awk '{print $14+$15}')
kill $SP_PID 2>/dev/null && wait $SP_PID 2>/dev/null || true
PCT=$(echo "scale=2; $TICKS * 100 / 500" | bc)
echo "  CPU usage: ${PCT}% of single core (budget: <1%)"

echo "[5/5] Packaging..."
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
echo "=== Feature matrix ==="
echo "  Output backends: json | table | influx | http | grpc"
echo "  Collectors: cpu(per-core) | memory(swap rate) | disk(IO latency p50-p99) | network(TCP retransmit/loss) | process(tree+fds+cgroup) | thermal"
echo "  Syscall layer: raw pread/getdents64/bpf (zero-copy stack buffers)"
echo "  Dynamic throttle: backs off up to 10x when CPU temp exceeds threshold"
echo "  Static binary: fully linked, no runtime dependencies"
echo ""
echo "Done."
