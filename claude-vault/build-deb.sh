#!/usr/bin/env bash
# Build the OpenShell .deb and supervisor image from this fork's claude-vault
# branch with podman, natively for this machine: amd64 on a PC, arm64 on a
# Raspberry Pi (64-bit OS). Run the same script on each machine. Nothing is
# installed; the install steps are printed at the end.
#
#   claude-vault/build-deb.sh
#   CARGO_BUILD_JOBS=2 claude-vault/build-deb.sh   # fewer parallel compiles (Pi with 4 GB)
#
# Needs: podman and git. The checkout is the repository this script is in.
#
# Output in claude-vault/dist/<arch>/:
#   openshell_<version>_<arch>.deb             CLI, gateway, prover, VM driver (stub), user unit
#   openshell-supervisor_<tag>_<arch>.tar      supervisor image with the Claude vault
#   openshell-sandbox_<tag>_<arch>.tar         sandbox runtime image (workload launcher)
#   bin/                                       the six built binaries
#
# Steps:
#   1. Version from git (deb/version.sh), as openshell-core/build.rs computes it:
#      latest vX.Y.Z tag, next patch, commits since, short sha -> 0.1.9-dev.25+g0ad0c122b.
#   2. deb/build-in-nix.sh in the builder image (deb/Containerfile.builder: Ubuntu
#      24.04 with Nix, like the release's Linux runners with setup-nix): the same build as a
#      GitHub release (the repo's Nix dev shell, cargo auditable build per binary,
#      musl CLI and prover, glibc 2.28 gateway and supervisor), then upstream's
#      tasks/scripts/package-deb.sh. `podman run`, not `podman build`: the dev
#      shell is several GB, and committing it as an image layer needs twice that
#      in free space. Instead the Nix store, cargo's downloads and the build
#      output live in named volumes (openshell-deb-nix, -cargo, -target), filled
#      on first use and reused after, so a rebuild only recompiles what changed.
#      `podman volume rm` them to reclaim the space.
#   3. deb/Containerfile.supervisor: the supervisor binary on upstream's
#      distroless base, tagged localhost/openshell/supervisor:<tag> and saved
#      with podman save (load it on another machine of the same architecture).
#   4. deb/Containerfile.sandbox: the static openshell-sandbox binary on scratch,
#      tagged localhost/openshell/sandbox:<tag> and saved the same way.
#
# Why the images: the gateway starts every sandbox from two OpenShell images, the
# supervisor (where the vault runs) and the sandbox runtime. By default it pulls
# them from ghcr.io with a tag equal to its own version, which doesn't exist for a
# dev build, so gateway.env points it at these local ones instead (install-deb.sh).
# The .deb only has the host binaries.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
ARCH=$(podman info --format '{{.Host.Arch}}')
NIX_IMAGE=docker.io/nixos/nix:2.31.5
OUT=$HERE/dist/$ARCH

branch=$(git -C "$REPO" rev-parse --abbrev-ref HEAD)
[[ "$branch" == *claude-vault || "$branch" == *claude-subscription-flow ]] || echo "warning: building branch $branch" >&2
if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=no -- crates providers proto deploy tasks Cargo.toml Cargo.lock)" ]]; then
    echo "warning: uncommitted changes go into this build" >&2
fi

# 1. Version.
cargo_version=$("$HERE/deb/version.sh" "$REPO")
image_tag="claude-vault-${cargo_version//+/-}"
echo "==> $ARCH, version $cargo_version, supervisor tag $image_tag"

# 2. Binaries and .deb, in the builder image (Ubuntu with Nix; small, built once).
BUILDER=localhost/openshell-deb-builder:latest
podman build -q -f "$HERE/deb/Containerfile.builder" --build-arg "NIX_IMAGE=$NIX_IMAGE" \
    -t "$BUILDER" "$HERE/deb" >/dev/null
rm -rf "$OUT"
mkdir -p "$OUT"
podman run --rm \
    -v openshell-deb-nix:/nix \
    -v openshell-deb-cargo:/root/.cargo \
    -v openshell-deb-target:/target \
    -v "$REPO:/src:ro" \
    -v "$HERE/deb:/deb:ro" \
    -v "$OUT:/out" \
    -e "CARGO_VERSION=$cargo_version" \
    -e "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-}" \
    "$BUILDER" bash /deb/build-in-nix.sh

# 3. Supervisor image.
image="localhost/openshell/supervisor:$image_tag"
podman build -f "$HERE/deb/Containerfile.supervisor" -t "$image" "$OUT/bin"
tar_file="$OUT/openshell-supervisor_${image_tag}_${ARCH}.tar"
podman save -o "$tar_file" "$image"

# 4. Sandbox runtime image.
runtime_image="localhost/openshell/sandbox:$image_tag"
podman build -f "$HERE/deb/Containerfile.sandbox" -t "$runtime_image" "$OUT/bin"
runtime_tar="$OUT/openshell-sandbox_${image_tag}_${ARCH}.tar"
podman save -o "$runtime_tar" "$runtime_image"

deb=$(ls "$OUT"/openshell_*.deb)
echo
echo "Built:"
ls -lh "$deb" "$tar_file" "$runtime_tar"
cat <<EOF

Install on this machine (replaces an installed openshell package, restarts the
gateway, points it at the two images, builds the Claude sandbox image and
imports the profiles; see the script's header):

  $HERE/install-deb.sh

The gateway must use the podman compute driver (the vault switch reaches
supervisors only through it).
Copy dist/$ARCH to another machine of the same architecture to install there.
EOF
