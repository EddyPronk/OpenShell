# The build container for ../build-deb.sh: an ordinary Linux userland with Nix,
# like the release's runners (a Linux host plus .github/actions/setup-nix).
#
# Why not docker.io/nixos/nix on its own: the flake's glibc toolchain links
# binaries with the standard loader path (/lib64/ld-linux-x86-64.so.2 or
# /lib/ld-linux-aarch64.so.1, nix/toolchain/linux.nix), so cargo's build scripts
# need a normal glibc system to run, which the nixos/nix image doesn't have.
#
# Nix itself is copied from the nixos/nix image. At run time build-deb.sh mounts
# the named volume openshell-deb-nix over /nix; podman fills it from this image
# on first use, and the dev shell then accumulates there.
ARG NIX_IMAGE=docker.io/nixos/nix:2.31.5
ARG BASE_IMAGE=docker.io/library/ubuntu:24.04

FROM ${NIX_IMAGE} AS nix

FROM ${BASE_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=nix /nix /nix
# Single-user Nix as root, no build users (the nixos/nix image's config names a
# nixbld group that doesn't exist here). The flake's binary cache is accepted.
RUN mkdir -p /etc/nix && printf '%s\n' \
      'build-users-group =' \
      'sandbox = false' \
      'experimental-features = nix-command flakes' \
      'accept-flake-config = true' \
      'trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=' \
      > /etc/nix/nix.conf
ENV PATH=/nix/var/nix/profiles/default/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    USER=root
