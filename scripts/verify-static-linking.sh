#!/bin/bash

# Script to verify that the musl build produces a statically linked library
# without libgcc_s.so.1 dependency - preventing regressions

set -e

# Build the musl target if not already built
if [ ! -f "target/x86_64-unknown-linux-musl/release/libscal3.so" ]; then
    # Check if the musl target is added
    if ! rustup target list --installed | grep -q "x86_64-unknown-linux-musl"; then
        rustup target add x86_64-unknown-linux-musl
    fi
    cargo build --release --target x86_64-unknown-linux-musl
fi

# Path to the built library
LIB_PATH="target/x86_64-unknown-linux-musl/release/libscal3.so"

if [ ! -f "$LIB_PATH" ]; then
    echo "Library not found at $LIB_PATH"
    exit 1
fi

# Check if statically linked
LDD_OUTPUT=$(ldd "$LIB_PATH" 2>&1 || true)
if ! echo "$LDD_OUTPUT" | grep -q "statically linked"; then
    echo "Library is not statically linked"
    exit 1
fi

# Check for libgcc dependency
if echo "$LDD_OUTPUT" | grep -q "libgcc_s.so"; then
    echo "Found unwanted libgcc_s.so dependency"
    exit 1
fi

# Check undefined symbols - should only be malloc and free
UNDEFINED_SYMBOLS=$(nm -D "$LIB_PATH" | grep "U " || true)
UNWANTED_SYMBOLS=$(echo "$UNDEFINED_SYMBOLS" | grep -v -E "(malloc|free)" || true)
if [ -n "$UNWANTED_SYMBOLS" ]; then
    echo "Found unexpected undefined symbols:"
    echo "$UNWANTED_SYMBOLS"
    exit 1
fi

echo "✅ Static linking verification passed"
