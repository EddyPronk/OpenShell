# Claude vault: Claude Code subscriptions in OpenShell sandboxes

This branch is an **unofficial fork** of [OpenShell](https://github.com/NVIDIA/OpenShell). It is
not made, reviewed or supported by NVIDIA or the OpenShell maintainers. It lets Claude Code use a
Claude Pro/Max subscription inside OpenShell sandboxes without the sandbox ever holding a real
token.

Claude Code runs unmodified and signs in with `/login` as usual. The sandbox's supervisor keeps
the real OAuth tokens and gives Claude Code ghost tokens instead, which it swaps for the real ones
on the way to Anthropic. Files, environment and memory in the sandbox only ever see ghosts.

> [!WARNING]
> The vault reuses Claude Code's own OAuth client and sign-in flow; Anthropic has not approved
> it for this. Check Anthropic's terms for your account before you use it. Try it at your own
> risk, with a gateway you run yourself.

Based on OpenShell `main` of 2026-11-11 (`86acdf985`), version `0.1.9-dev`. Tested with the
podman compute driver on amd64 (Debian 13) and arm64 (Raspberry Pi CM4), Claude Code 2.1.32x.

## Upstream status

OpenShell's accepted direction for subscription providers is
[#3331](https://github.com/NVIDIA/OpenShell/issues/3331): a provider-neutral `openshell provider
login`, where the gateway obtains and refreshes a grant of its own, for Codex and Claude alike.
That needs a client registered with Anthropic, so it doesn't exist for Claude yet. Signing in
inside the sandbox, as this fork does, is one of the alternatives #3331 rejects.

The part of this fork that fits #3331 is the token swap: the workload holds a placeholder and
the supervisor substitutes the real credential, including in the client's own refresh, sign-in
and logout requests. Upstream it would have to be provider-neutral (Codex's ChatGPT login has the
same shape) rather than Claude-specific. Until then, this fork is a way to use the feature today.

## How it works

```
Claude Code (sandbox)  ── ghost tokens ──►  supervisor's vault  ── real tokens ──►  Anthropic
   ~/.claude/.credentials.json                (TLS-terminating proxy)
   holds agent-mitm-proxy-oat-… ghosts        swaps ghosts for real tokens, answers
                                              Claude Code's refresh, /login and /logout
```

The supervisor already terminates TLS for policy enforcement. The vault hooks into that L7
relay for Claude Code's hosts (`api.anthropic.com`, `platform.claude.com`,
`mcp-proxy.anthropic.com`), only for `/usr/local/bin/claude` and `/usr/bin/curl`:

- A `/login` goes to Anthropic for real; the vault keeps the tokens it returns and hands Claude
  Code ghosts.
- Requests with a ghost access token go out with the real one.
- Claude Code's own token refresh is answered locally with fresh ghosts; the real refresh
  happens elsewhere (below), so there's exactly one owner of the refresh token.

### Two login modes

The provider attached to a sandbox picks the mode.

| | Shared login | Sandbox login |
|---|---|---|
| Provider type (profile) | `claude-code-shared-login` | `claude-code-sandbox-login` |
| Sign-in | `/login` once, in any sandbox with the provider | `/login` in each sandbox |
| Real refresh token | Only in the gateway, which refreshes it | In that sandbox's supervisor (tmpfs) |
| New sandboxes | Start signed in | Need their own `/login` |
| Sign-in lost when | The provider is deleted | The sandbox or its supervisor goes away |
| Use for | Day-to-day work: many sandboxes, one sign-in | A second account, or a throwaway sandbox |

In shared login, the supervisor submits a `/login` to the gateway, which stores the grant
through its credential driver and refreshes it with OpenShell's provider refresh machinery
(every 8 hours, 30 minutes before expiry). Every supervisor reads the current access token
from the gateway like any provider credential, but keeps it out of the sandbox's environment.

### What the fork changes

| Where | What |
|---|---|
| `crates/openshell-supervisor-network/src/l7/claude_vault.rs` | The vault: ghost tokens, swap, local refresh/login/logout handling, sign-in submission |
| `crates/openshell-supervisor-network/src/l7/relay.rs` | Calls the vault for each inspected HTTP request |
| `crates/openshell-supervisor/src/lib.rs` | Keeps the shared token out of the sandbox's environment |
| `crates/openshell-server/src/grpc/claude_vault.rs`, `proto/claude_vault.proto` | Gateway side of shared login: accepts a sign-in from a supervisor, installs it as the provider's credential and refresh material |
| `crates/openshell-driver-podman/src/container.rs` | Passes `OPENSHELL_CLAUDE_VAULT` from the gateway's environment to supervisors |
| `providers/claude-code-*-login.yaml` | The two provider profiles |
| `claude-vault/` | This guide, build and install scripts, the Claude sandbox image and policy |

Each change to upstream code is marked with a `Personal patch` comment
(`git grep -n 'Personal patch'`). The vault is off unless the gateway runs with
`OPENSHELL_CLAUDE_VAULT=on`; otherwise this build behaves like upstream.

## Requirements

- Linux with **podman** and the OpenShell gateway using the **podman compute driver**. The vault
  switch reaches supervisors only through that driver.
- About 15 GB of disk for the build caches (the Nix dev shell and cargo's output), and patience
  on a Pi: the first build takes about an hour there.

## Install

The build makes a `.deb` like an OpenShell release, plus the patched supervisor and sandbox
runtime images, for the machine it runs on (amd64 or arm64):

```shell
git clone -b feature/claude-subscription-flow https://github.com/EddyPronk/OpenShell.git
cd OpenShell
claude-vault/build-deb.sh     # output in claude-vault/dist/<arch>/
claude-vault/install-deb.sh   # uses sudo for apt; restarts the gateway
```

`install-deb.sh`:

1. installs the `.deb` (replacing an installed `openshell` package);
2. loads the two images into podman;
3. writes `OPENSHELL_CLAUDE_VAULT=on` and the two image names into
   `~/.config/openshell/gateway.env`, so the gateway doesn't try to pull
   `ghcr.io/nvidia/openshell/...:<dev version>`, which doesn't exist;
4. restarts the gateway;
5. builds the Claude sandbox image `localhost/claude-sandbox:latest`
   ([claude-sandbox/Containerfile](claude-sandbox/Containerfile)) if missing;
6. imports or updates both provider profiles.

The build caches live in the podman volumes `openshell-deb-nix`, `openshell-deb-cargo` and
`openshell-deb-target`; keep them for fast rebuilds. To build on one machine and install on
another of the same architecture, copy `claude-vault/dist/<arch>/` along with the checkout.

Running sandboxes keep their old supervisor: recreate them after an install.

**Back to the official package:** `sudo apt install --allow-downgrades openshell=<version>`,
remove the three lines from `gateway.env`, and restart the gateway
(`systemctl --user restart openshell-gateway`).

## Shared login

Once per gateway, create the provider with no credential:

```shell
openshell provider create --name claude-shared --type claude-code-shared-login
```

Create a sandbox with it. Without a command its main process is a shell, and `create` attaches
to it:

```shell
openshell sandbox create --name test --from localhost/claude-sandbox:latest \
    --provider claude-shared --policy claude-vault/claude-sandbox/policy.yaml
```

[`claude-sandbox/policy.yaml`](claude-sandbox/policy.yaml) is OpenShell's default policy plus
working terminals (`/dev/pts`, needed by VS Code's terminal and tmux) and GitHub, PyPI, npm, uv
and VS Code hosts. Without `--policy` you get the default, which reaches only the Anthropic hosts.

In that shell, fetch the ghost credentials file, then start Claude Code:

```shell
curl -fsS --create-dirs -o ~/.claude/.credentials.json \
    https://platform.claude.com/openshell-claude-vault/credentials
claude
```

The supervisor answers that URL itself; nothing goes to Anthropic. The very first time, before
the gateway has a grant, `curl` fails: run `claude` and `/login` instead. From then on every
sandbox with `claude-shared`, existing or new, works without `/login`.

Check the grant:

```shell
openshell provider refresh status claude-shared
```

`STATUS` is `configured` after a sign-in and `refreshed` after each refresh.

Leave the shell with Ctrl-P Ctrl-Q to keep it running, and come back with
`openshell sandbox connect test`. Don't type `exit` there: that shell is the sandbox's main
process, so ending it ends the sandbox. Bring it back with `openshell sandbox stop test`, then
`openshell sandbox start test`. For extra shells use `openshell sandbox exec test --tty -- bash`,
where `exit` is harmless.

## Sandbox login

```shell
openshell provider create --name claude-own --type claude-code-sandbox-login
openshell sandbox create --name claude-x --from localhost/claude-sandbox:latest --provider claude-own
claude      # in the sandbox's shell, then /login
```

The supervisor refreshes this sandbox's grant itself. `/logout` revokes it upstream.

## Network access

A sandbox reaches only what its policy names, per host and per program. See what was blocked:

```shell
openshell logs test | grep DENIED
```

Add hosts to a running sandbox; `--binary` names the programs that may use them:

```shell
openshell policy update test --add-endpoint example.com:443 --binary /usr/bin/curl --wait
```

The sandbox user has no root, so install tools into the home directory (for example uv, which
can then install Python) or into the image.

## Working from a laptop (VS Code)

The gateway listens on 127.0.0.1 with mTLS. To use it from another machine:

1. Copy the gateway host's CLI client certificate. Don't make a new one: the gateway maps the
   certificate's CN to the user, and another CN wouldn't see your sandboxes.

   ```shell
   mkdir -p -m 700 ~/.config/openshell/gateways/remote/mtls
   scp -p 'gateway-host:.config/openshell/gateways/openshell/mtls/*' ~/.config/openshell/gateways/remote/mtls/
   ```

2. Run an ssh tunnel to the gateway: [laptop/openshell-gateway-tunnel.service](laptop/openshell-gateway-tunnel.service),
   with `gateway-host` replaced. It uses local port 17671, in case the laptop runs its own
   gateway on 17670.

3. Register the gateway, then switch the default back if you have a local one:

   ```shell
   openshell gateway add https://127.0.0.1:17671 --remote gateway-host --name remote
   openshell gateway select openshell
   ```

Then:

```shell
openshell -g remote sandbox connect test --editor vscode
```

That needs no SSH keys for the sandbox: the SSH session runs through the gateway, authenticated
by the CLI's certificate. It runs once per sandbox name; afterwards VS Code reconnects to the
host `openshell-test.default` by itself. VS Code's terminal needs `/dev/pts` and its server needs
Microsoft's download hosts, both in the policy above.

## Day to day

| Situation | What to do |
|---|---|
| Sign in with another account, or the grant is broken | `/login` in any shared-login sandbox. It replaces the gateway's grant for every sandbox |
| `refresh status` says `reauthorization_required` | Same: `/login` in one sandbox |
| Force a refresh now | `openshell provider refresh rotate claude-shared` |
| `/logout` in a shared-login sandbox | Only that Claude Code signs out. Fetch the credentials file again to sign back in |
| Stop all sandboxes using the subscription | `openshell provider delete claude-shared` |
| Turn the vault off | Remove `OPENSHELL_CLAUDE_VAULT=on` from `gateway.env`, restart the gateway, recreate sandboxes |

## Seeing what it does

```shell
openshell logs <sandbox> | grep claude-vault
```

Each token request is logged as an OCSF HTTP event with a `claude-vault:` policy name, never
with token values:

| Event | Meaning |
|---|---|
| `claude-vault:sign-in` | A `/login` went to Anthropic |
| `claude-vault:sign-in-accepted` | The gateway took the sign-in over (shared login) |
| `claude-vault:sign-in-kept` | The gateway refused it; the sandbox keeps it as sandbox login |
| `claude-vault:sign-in-not-submitted` | The gateway couldn't be asked; sandbox login |
| `claude-vault:revoked` | `/logout` in sandbox login |

## Limits

- Claude Code only, at `/usr/local/bin/claude`. Other clients aren't handled.
- One shared-login provider per sandbox. A sandbox with two is refused a sign-in.
- In shared login, every sandbox with the provider can use the subscription, and a compromised
  agent can use it while it runs. It can't take a working token out of the sandbox.
- Sandbox login's grant lives in the supervisor's tmpfs: a supervisor restart loses it.
- Podman compute driver only.

## Developing

Run a dev gateway from the checkout with `OPENSHELL_CLAUDE_VAULT=on mise run gateway:podman`
and use it as `openshell -g podman-dev`. Its sandboxes need `OPENSHELL_SUPERVISOR_IMAGE` and
`OPENSHELL_SANDBOX_RUNTIME_IMAGE` pointing at local images built from this branch.
