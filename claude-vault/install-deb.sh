#!/usr/bin/env bash
# Install the .deb and supervisor image that build-deb.sh made on this machine,
# and set the gateway up for the Claude vault. Run it on the machine itself
# (amd64 PC or arm64 Pi); it uses sudo for apt only.
#
#   claude-vault/install-deb.sh
#
# Steps:
#   1. sudo apt install dist/<arch>/openshell_<version>_<arch>.deb
#      (replaces an installed openshell package, e.g. the official 0.1.8).
#   2. The images localhost/openshell/supervisor:<tag> and
#      localhost/openshell/sandbox:<tag>: already in podman after build-deb.sh on
#      this machine, else loaded from dist/<arch>/*.tar. No registry needed: the
#      podman driver uses local images.
#   3. ~/.config/openshell/gateway.env (read by the gateway's systemd user unit):
#        OPENSHELL_CLAUDE_VAULT=on
#        OPENSHELL_SUPERVISOR_IMAGE=localhost/openshell/supervisor:<tag>
#        OPENSHELL_SANDBOX_RUNTIME_IMAGE=localhost/openshell/sandbox:<tag>
#      Without the two image lines the gateway pulls ghcr.io/nvidia/openshell/...:<its
#      version>, which doesn't exist for a dev build. Existing lines for these
#      keys are replaced; others are kept.
#   4. systemctl --user restart openshell-gateway, then wait until it answers.
#      Running sandboxes keep their old supervisor until recreated.
#   5. The Claude sandbox image localhost/claude-sandbox:latest
#      (claude-sandbox/Containerfile), built here if missing.
#   6. The provider profiles claude-code-sandbox-login and claude-code-shared-login
#      (providers/ in this repository): imported if missing, else updated to the repo's
#      version (an update needs the gateway's current resource_version, taken
#      from an export).
#
# Afterwards, for shared login: create a provider of type claude-code-shared-login
# with no credential, start a sandbox with it and /login there once. The
# supervisor hands the sign-in to the gateway (the profile's
# claude-vault.openshell.dev/sign-in annotation allows it), and every later
# sandbox with that provider starts signed in. The closing message prints the
# commands.
#
# Back to the official package: sudo apt install --allow-downgrades openshell=<version>,
# remove the three lines from ~/.config/openshell/gateway.env, restart the gateway.
# (The gateway's database may have been migrated by the newer version.)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
ARCH=$(dpkg --print-architecture)
OUT=$HERE/dist/$ARCH
ENV_FILE=${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateway.env
SANDBOX_IMAGE=localhost/claude-sandbox:latest

deb=$(ls -t "$OUT"/openshell_*_"$ARCH".deb | head -1)
tar_file=$(ls -t "$OUT"/openshell-supervisor_*_"$ARCH".tar | head -1)
tag=$(basename "$tar_file" "_$ARCH.tar")
tag=${tag#openshell-supervisor_}
image=localhost/openshell/supervisor:$tag
runtime_tar=$OUT/openshell-sandbox_${tag}_$ARCH.tar
runtime_image=localhost/openshell/sandbox:$tag
echo "==> package $(basename "$deb"), images $image and $runtime_image"

# 1. Package.
sudo apt-get install -y "$deb"
openshell --version

# 2. Supervisor image.
if ! podman image exists "$image"; then
    podman load -i "$tar_file"
fi
if ! podman image exists "$runtime_image"; then
    podman load -i "$runtime_tar"
fi

# 3. Gateway environment.
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"
tmp=$(mktemp)
grep -v -E '^(OPENSHELL_CLAUDE_VAULT|OPENSHELL_SUPERVISOR_IMAGE|OPENSHELL_SANDBOX_RUNTIME_IMAGE)=' "$ENV_FILE" >"$tmp" || true
printf 'OPENSHELL_CLAUDE_VAULT=on\nOPENSHELL_SUPERVISOR_IMAGE=%s\nOPENSHELL_SANDBOX_RUNTIME_IMAGE=%s\n' \
    "$image" "$runtime_image" >>"$tmp"
mv "$tmp" "$ENV_FILE"
echo "==> $ENV_FILE:"
cat "$ENV_FILE"

# 4. Gateway.
systemctl --user daemon-reload
systemctl --user enable openshell-gateway >/dev/null 2>&1 || true
systemctl --user restart openshell-gateway
for _ in $(seq 60); do
    openshell sandbox list >/dev/null 2>&1 && break
    sleep 2
done
systemctl --user is-active openshell-gateway
openshell sandbox list

# 5. Sandbox image.
if ! podman image exists "$SANDBOX_IMAGE"; then
    podman build -t "$SANDBOX_IMAGE" "$HERE/claude-sandbox"
fi

# 6. Provider profiles.
for profile in claude-code-sandbox-login claude-code-shared-login; do
    file=$REPO/providers/$profile.yaml
    if ! openshell provider profile describe "$profile" >/dev/null 2>&1; then
        openshell provider profile import -f "$file"
    else
        version=$(openshell provider profile export "$profile" | sed -n 's/^resource_version: //p')
        tmp=$(mktemp --suffix=.yaml)
        { echo "resource_version: $version"; cat "$file"; } >"$tmp"
        openshell provider profile update "$profile" -f "$tmp"
        rm -f "$tmp"
    fi
done

cat <<EOF

Installed. For shared login, create the provider (once, no credential) and a
sandbox with it; see claude-vault/README.md:

  openshell provider create --name claude-shared --type claude-code-shared-login
  openshell sandbox create --name test --from $SANDBOX_IMAGE --provider claude-shared \\
      --policy $HERE/claude-sandbox/policy.yaml

In the sandbox's shell:

  curl -fsS --create-dirs -o ~/.claude/.credentials.json https://platform.claude.com/openshell-claude-vault/credentials
  claude      # the very first time curl fails: /login once in Claude Code

Running sandboxes keep their old supervisor: recreate them to get this build's.
EOF
