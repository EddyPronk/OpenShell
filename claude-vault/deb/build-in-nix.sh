#!/usr/bin/env bash
# Builds the six binaries the way a GitHub release does, then the .deb.
#
# Two ways in:
#   - In the builder container (Containerfile.builder) started by ../build-deb.sh,
#     with no arguments: copies /src to /work and enters `nix develop` there.
#   - On a host with Nix (the fork's CI, or a Nix user), from the checkout's root:
#       CARGO_VERSION=$(claude-vault/deb/version.sh) \
#           nix develop -c bash claude-vault/deb/build-in-nix.sh inner
#     This edits the version in the checkout's Cargo.toml, like the release does.
#     Output goes to $OUT_DIR (default claude-vault/dist/<amd64|arm64>), cargo's to
#     $CARGO_TARGET_DIR (default ./target).
#
# Mounts (set up by build-deb.sh):
#   /src      the OpenShell checkout, read-only
#   /deb      this directory, read-only
#   /out      output directory on the host (dist/<arch>)
#   /nix      named volume: the Nix store with the dev shell, kept between builds
#   /root/.cargo, /target   named volumes: cargo downloads and build output
#
# Same toolchain as the release (.github/workflows/build-binaries-linux.yml with
# .github/actions/build-rust-binary): the repo's Nix dev shell (flake.nix), and per
# binary `cargo auditable build --release --target <triple>` with git versioning
# off and the version stamped into Cargo.toml:
#   openshell, openshell-prover, openshell-sandbox       <arch>-unknown-linux-musl (static)
#   openshell-gateway, openshell-supervisor, VM driver   <arch>-unknown-linux-gnu (glibc 2.28 sysroot)
# z3 and aws-lc come from the flake's Nix packages, as in the release. The VM
# driver is built without its runtime bundle (not needed here).
set -euo pipefail

if [[ "${1:-}" == inner ]]; then
    # Inside `nix develop`.
    : "${CARGO_VERSION:?}"
    # The release stamps the version into Cargo.toml (build-rust-binary "Set
    # version"). The flake was already copied to the store from /work, so this
    # edit doesn't change the dev shell.
    sed -i "s/^version = \"0\\.0\\.0\"$/version = \"${CARGO_VERSION}\"/" Cargo.toml
    grep -A1 '^\[workspace.package\]' Cargo.toml
    if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then export CARGO_BUILD_JOBS; else unset CARGO_BUILD_JOBS; fi
    # The container mounts /out and /target; on a host they default into the checkout.
    case $(uname -m) in x86_64) deb_arch=amd64 ;; aarch64) deb_arch=arm64 ;; *) deb_arch=$(uname -m) ;; esac
    if [[ -d /out ]]; then out=${OUT_DIR:-/out}; else out=${OUT_DIR:-$PWD/claude-vault/dist/$deb_arch}; fi
    if [[ -d /target ]]; then target=${CARGO_TARGET_DIR:-/target}; else target=${CARGO_TARGET_DIR:-$PWD/target}; fi
    export GIT_DIR=/nonexistent CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$target
    arch=$(uname -m)
    musl=$arch-unknown-linux-musl
    gnu=$arch-unknown-linux-gnu
    build() { cargo auditable build --release --target "$1" --package "$2" --bin "$3"; }
    build "$musl" openshell-cli openshell
    build "$musl" openshell-prover-cli openshell-prover
    build "$musl" openshell-sandbox openshell-sandbox
    build "$gnu" openshell-gateway openshell-gateway
    build "$gnu" openshell-supervisor openshell-supervisor
    build "$gnu" openshell-driver-vm openshell-driver-vm

    mkdir -p "$out/bin"
    install -m 0755 "$target/$musl/release/openshell" "$target/$musl/release/openshell-prover" \
        "$target/$musl/release/openshell-sandbox" "$out/bin/"
    install -m 0755 "$target/$gnu/release/openshell-gateway" "$target/$gnu/release/openshell-supervisor" \
        "$target/$gnu/release/openshell-driver-vm" "$out/bin/"
    for b in "$out"/bin/*; do "$b" --version || true; done

    # Upstream's packager; Debian version 0.1.9-dev.25+g<sha> -> 0.1.9~dev.25+g<sha>.claudevault
    OPENSHELL_CLI_BINARY="$out/bin/openshell" \
    OPENSHELL_GATEWAY_BINARY="$out/bin/openshell-gateway" \
    OPENSHELL_PROVER_BINARY="$out/bin/openshell-prover" \
    OPENSHELL_DRIVER_VM_BINARY="$out/bin/openshell-driver-vm" \
    OPENSHELL_DEB_VERSION="${CARGO_VERSION/-/\~}.claudevault" \
    OPENSHELL_OUTPUT_DIR="$out" \
        tasks/scripts/package-deb.sh >/dev/null
    ls -l "$out"
    exit 0
fi

# A writable copy of the source (the flake is evaluated from it; target/ and .git
# stay out, so Nix doesn't copy them into its store).
rm -rf /work
mkdir -p /work
tar -C /src --exclude=./target --exclude=./.git --exclude=./.cache --exclude=./claude-vault/dist \
    -cf - . | tar -C /work -xf -

cd /work
exec nix develop path:/work -c bash /deb/build-in-nix.sh inner
