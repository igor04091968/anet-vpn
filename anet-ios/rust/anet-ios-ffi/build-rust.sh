#!/bin/sh
set -eu

: "${SRCROOT:?Run this script from an Xcode build phase}"
: "${PLATFORM_NAME:?Missing Xcode PLATFORM_NAME}"
: "${CURRENT_ARCH:?Missing Xcode CURRENT_ARCH}"

REPO_ROOT="$(cd "${SRCROOT}/../.." && pwd)"
MANIFEST="${SRCROOT}/../rust/anet-ios-ffi/Cargo.toml"
CARGO_BIN="$(command -v cargo || true)"
if [ -z "${CARGO_BIN}" ] && [ -x "${HOME}/.cargo/bin/cargo" ]; then
  CARGO_BIN="${HOME}/.cargo/bin/cargo"
fi
if [ -z "${CARGO_BIN}" ] || [ ! -x "${CARGO_BIN}" ]; then
  echo "Cargo was not found. Install Rust and make cargo available to Xcode." >&2
  exit 2
fi

case "${PLATFORM_NAME}:${CURRENT_ARCH}" in
  iphoneos:arm64) RUST_TARGET="aarch64-apple-ios" ;;
  iphonesimulator:arm64) RUST_TARGET="aarch64-apple-ios-sim" ;;
  iphonesimulator:x86_64) RUST_TARGET="x86_64-apple-ios" ;;
  *) echo "Unsupported iOS build target: ${PLATFORM_NAME}/${CURRENT_ARCH}" >&2; exit 2 ;;
esac

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
export CARGO_INCREMENTAL=0
"${CARGO_BIN}" build --release --manifest-path "${MANIFEST}" --target "${RUST_TARGET}" --lib
mkdir -p "${BUILT_PRODUCTS_DIR}"
cp "${REPO_ROOT}/target/${RUST_TARGET}/release/libanet_ios_ffi.a" \
  "${BUILT_PRODUCTS_DIR}/libanet_ios_ffi.a"
