#!/bin/bash
set -e

# Configuration
BUILD_DIR="../build"
PASS_SO="$BUILD_DIR/libSQLiPass.so"
CLANG="clang"
OPT="opt"

# Ensure build exists
if [ ! -f "$PASS_SO" ]; then
    echo "Pass library not found at $PASS_SO. Building..."
    cmake -S ../src -B "$BUILD_DIR"
    cmake --build "$BUILD_DIR"
fi

TEST_FILE="${1:-test_vulnerable.cpp}"

if [ ! -f "$TEST_FILE" ]; then
    echo "Error: Test file '$TEST_FILE' not found."
    exit 1
fi

BASE_NAME=$(basename "$TEST_FILE" .cpp)

echo "========================================"
echo "Testing $BASE_NAME..."
echo "========================================"

# Compile to LLVM IR
"$CLANG" -S -emit-llvm -O0 -Xclang -disable-O0-optnone "$TEST_FILE" -o "$BUILD_DIR/${BASE_NAME}.ll"

# Run opt pass and print output
# We use || true so that if opt fails or returns a non-zero exit code, the script doesn't abort.
"$OPT" -load-pass-plugin="$PASS_SO" -passes="hello-sqli" "$BUILD_DIR/${BASE_NAME}.ll" -o "$BUILD_DIR/${BASE_NAME}_out.ll" -S 2> "$BUILD_DIR/${BASE_NAME}.err" || true
OUTPUT=$(cat "$BUILD_DIR/${BASE_NAME}.err")

echo "$OUTPUT"
echo "----------------------------------------"
echo "IR output saved to $BUILD_DIR/${BASE_NAME}_out.ll"

# CFG output is created in the working directory (tests), move it to build directory
mv cfg_output.json "$BUILD_DIR/${BASE_NAME}_cfg.json" 2>/dev/null || true
