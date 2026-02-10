#!/bin/bash
# Erebus XLL Payload Build Script
# Cross-compiles XLL DLLs from Linux using MinGW-w64
# Usage: ./build_xll.sh <source_file> <output_file> [arch] [optimization] [extra_libs]

set -e

# Parse arguments
SOURCE_FILE="${1:?Error: Source file required}"
OUTPUT_FILE="${2:?Error: Output file required}"
ARCH="${3:-x64}"
OPTIMIZATION="${4:-Ox}"
EXTRA_LIBS="${5:-}"

# Resolve to absolute paths
SOURCE_FILE="$(cd "$(dirname "$SOURCE_FILE")" && pwd)/$(basename "$SOURCE_FILE")"
OUTPUT_FILE="$(cd "$(dirname "$OUTPUT_FILE")" && pwd)/$(basename "$OUTPUT_FILE")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Validate source file
if [ ! -f "$SOURCE_FILE" ]; then
    echo "[-] Source file not found: $SOURCE_FILE"
    exit 1
fi

# Check for MinGW-w64
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "[-] MinGW-w64 not found. Install with: apt-get install mingw-w64"
    exit 1
fi

echo "[*] Building XLL payload..."
echo "[*] Source: $SOURCE_FILE"
echo "[*] Output: $OUTPUT_FILE"
echo "[*] Architecture: $ARCH"
echo "[*] Optimization: $OPTIMIZATION"

# Copy source to build directory
BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

cp "$SOURCE_FILE" "$BUILD_DIR/payload.cpp"

# Build using Makefile
cd "$BUILD_DIR"
make -f "$SCRIPT_DIR/Makefile" \
    XLL_SOURCE="payload.cpp" \
    XLL_OUTPUT="payload.xll" \
    ARCH="$ARCH" \
    OPTIMIZATION="$OPTIMIZATION" \
    EXTRA_LIBS="$EXTRA_LIBS" \
    VERBOSE=1

# Copy output to final location
if [ -f "$BUILD_DIR/payload.xll" ]; then
    cp "$BUILD_DIR/payload.xll" "$OUTPUT_FILE"
    echo "[+] XLL compiled successfully: $OUTPUT_FILE"
    ls -lh "$OUTPUT_FILE"
    exit 0
else
    echo "[-] Compilation failed: $BUILD_DIR/payload.xll not created"
    exit 1
fi
