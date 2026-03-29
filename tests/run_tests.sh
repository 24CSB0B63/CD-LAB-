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

echo "========================================"
echo "Running SQLi Pass Tests"
echo "========================================"

run_test() {
    local TEST_FILE="$1"
    local EXPECT_VULN="$2"
    local BASE_NAME=$(basename "$TEST_FILE" .cpp)
    
    echo ">> Testing $BASE_NAME..."
    
    # Compile to LLVM IR
    # -O0 to preserve structure, -g for debug info (optional, helps reading IR)
    # -disable-O0-optnone is crucial effectively to allow opt passes to run effectively if method attributes prevent it
    "$CLANG" -S -emit-llvm -O0 -Xclang -disable-O0-optnone "$TEST_FILE" -o "$BUILD_DIR/${BASE_NAME}.ll"

    # Check IR modification for __sqli_warning
    if [ "$EXPECT_VULN" = "true" ]; then
        # The modified .ll is not saved back by default if we use -disable-output, 
        # so let's run opt and save output, then check it.
        "$OPT" -load-pass-plugin="$PASS_SO" -passes="hello-sqli" "$BUILD_DIR/${BASE_NAME}.ll" -o "$BUILD_DIR/${BASE_NAME}_out.ll" -S 2> "$BUILD_DIR/${BASE_NAME}.err"
        OUTPUT=$(cat "$BUILD_DIR/${BASE_NAME}.err")
        echo "$OUTPUT"

        if echo "$OUTPUT" | grep -q "VULNERABILITY DETECTED"; then
            echo "✅ PASS: Vulnerability correctly detected."
        else
            echo "❌ FAIL: Expected vulnerability warning but none found."
            exit 1
        fi

        if grep -q "__sqli_warning" "$BUILD_DIR/${BASE_NAME}_out.ll"; then
            echo "✅ PASS: __sqli_warning correctly injected into IR."
        else
            echo "❌ FAIL: Expected __sqli_warning injection but none found."
            exit 1
        fi

        if echo "$OUTPUT" | grep -q "\[PATTERN\]"; then
            echo "✅ PASS: SQL pattern correctly detected during concatenation."
        else
            echo "❌ FAIL: Expected SQL string pattern match but none found."
            exit 1
        fi
    else

        OUTPUT=$("$OPT" -load-pass-plugin="$PASS_SO" -passes="hello-sqli" -disable-output "$BUILD_DIR/${BASE_NAME}.ll" 2>&1)
        echo "$OUTPUT"

        if echo "$OUTPUT" | grep -q "VULNERABILITY DETECTED"; then
            echo "❌ FAIL: False positive detected!"
            exit 1
        else
            echo "✅ PASS: No false positive."
        fi
    fi
    # CFG output is created in the working directory (tests), move it to build directory
    mv cfg_output.json "$BUILD_DIR/${BASE_NAME}_cfg.json" 2>/dev/null || true
    echo "----------------------------------------"
}

# Run tests
# run_test "test_vulnerable.cpp" "true"
# run_test "test_safe.cpp" "false"
# run_test "test_interprocedural.cpp" "true"
# run_test "test_demo.cpp" "true"
# run_test "test_sanitized.cpp" "false"
run_test "test_sample.cpp" "true"

echo "All tests passed!"
