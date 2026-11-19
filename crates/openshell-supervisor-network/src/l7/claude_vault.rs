// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Personal patch: a credential vault for Claude Code subscription logins.
//!
//! A port of agent-mitm-proxy's `CredentialVaultPlugin`. Claude Code signs in
//! inside the sandbox as usual; this module follows the OAuth flow from the
//! middle, so no real token ever reaches the sandbox:
//!
//! - **Sign-in:** the token response's real tokens are kept in the vault (a
//!   file in the supervisor's private tmpfs); the sandbox gets ghost tokens,
//!   `agent-mitm-proxy-oat-<48 hex>` and `agent-mitm-proxy-ort-<48 hex>`.
//! - **Every other request to [`VAULT_HOSTS`]:** `Authorization: Bearer <ghost>`
//!   (or `x-api-key`) is swapped for the real access token.
//! - **Refresh:** the ghosts never change, so the vault answers a refresh
//!   itself unless the real access token needs one (it expires within
//!   [`REFRESH_MARGIN`], or a request with the current token got a 401). Then
//!   one refresh goes upstream with the real refresh token swapped in.
//! - **Adoption:** a refresh with a real refresh token goes upstream and its
//!   response is kept like a sign-in's.
//! - **Revoke:** the ghost in the body is swapped for the real token; a 2xx
//!   drops the grant.
//!
//! Token responses are rewritten whole. One the vault can't read, or one with
//! tokens where none were expected, gets the sandbox a 502.
//!
//! **Shared login.** When the sandbox has a provider with the credential
//! [`SHARED_KEY`] (profile `claude-code-shared-login`), the gateway holds one
//! grant for every such sandbox and is the only party that refreshes it. The
//! vault then keeps no grant of its own:
//!
//! - any access ghost on a vault host is swapped for the provider's current
//!   token, read on every request so a new revision takes effect at once (every
//!   sandbox with the provider may use that token, so a ghost needs no record);
//! - refreshes are answered locally with ghosts and the token's expiry, never
//!   forwarded; a refresh with a real refresh token is refused, since
//!   forwarding it would make a second refresher;
//! - a sign-in (`/login`) is a real one: forwarded, recorded and offered to the
//!   gateway as below, so it replaces the shared grant when the profile allows;
//! - `/logout` is answered locally, so the shared grant stays;
//! - `GET https://platform.claude.com` [`DELIVERY_PATH`] answers with a
//!   ghost `.credentials.json`, so a new sandbox starts signed in.
//!
//! The supervisor removes [`SHARED_KEY`] from the sandbox's environment
//! ([`hidden_env_keys`]), so its placeholder can't end up in a conversation.
//!
//! **Signing in for shared login.** While the provider has no usable token, the
//! sandbox is in sandbox login, so `/login` is recorded here. The vault then
//! offers the grant to the gateway (`ClaudeVault/SubmitProviderSignIn`). The
//! gateway accepts it only if the profile of an attached provider allows a
//! sandbox sign-in; the vault then forgets the real refresh token, and shared
//! login takes over when the provider's token arrives. If the gateway refuses
//! or can't be reached, the sandbox simply stays in sandbox login.
//!
//! The vault is on only when the supervisor has `OPENSHELL_CLAUDE_VAULT=on`.
//! The podman driver copies that variable from the gateway's environment. The
//! switch is deliberately not a provider credential: those show up in the
//! sandbox's environment as placeholders, and a placeholder that reaches the
//! conversation history makes every later request body get refused.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use miette::{IntoDiagnostic, Result};
use openshell_core::grpc_client::GatewayEndpoint;
use openshell_core::proto::SubmitProviderSignInRequest;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, SeverityId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::l7::provider::{BodyLength, L7Request};
use crate::l7::relay::L7EvalContext;
use crate::telemetry::egress_emit;

/// Hosts that get the real access token (over TLS on port 443 only).
pub(crate) const VAULT_HOSTS: [&str; 3] = [
    "api.anthropic.com",
    "platform.claude.com",
    "mcp-proxy.anthropic.com",
];
const TOKEN_HOST: &str = "platform.claude.com";
const TOKEN_PATH: &str = "/v1/oauth/token";
const REVOKE_PATH: &str = "/v1/oauth/token/revoke";
/// A real access token with less than this many seconds left is refreshed upstream.
pub(crate) const REFRESH_MARGIN: i64 = 300;
/// Refreshes within this many seconds of one sent upstream are answered locally.
pub(crate) const REFRESH_INFLIGHT: f64 = 30.0;
const GHOST_PREFIX: &str = "agent-mitm-proxy";
const TOKEN_FIELDS: [&str; 3] = ["access_token", "refresh_token", "id_token"];
const MAX_BODY: usize = 1 << 20;
const ENV_SWITCH: &str = "OPENSHELL_CLAUDE_VAULT";
const ENV_DIR: &str = "OPENSHELL_CLAUDE_VAULT_DIR";
const DEFAULT_DIR: &str = "/run/openshell-claude-vault";
/// Shared login: the provider credential holding the gateway's access token.
pub const SHARED_KEY: &str = "CLAUDE_ACCESS_TOKEN";
/// Shared login: where a sandbox fetches its ghost credentials file.
pub(crate) const DELIVERY_PATH: &str = "/openshell-claude-vault/credentials";
/// Shared login: the scopes a subscription sign-in grants (2026-11-12 capture).
const SHARED_SCOPES: &str =
    "user:file_upload user:inference user:mcp_servers user:plugins user:profile user:sessions:claude_code";
/// Shared login: Claude Code is told its token expires this long before the
/// gateway's, so it doesn't use the token in its last minute.
const SHARED_EXPIRY_MARGIN_MS: i64 = 60_000;
/// Shared login: the lifetime given out when the gateway sets no expiry.
const SHARED_DEFAULT_EXPIRES_IN: i64 = 3600;
/// How long the vault waits for the gateway to take a sign-in.
const SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Vault state
// ---------------------------------------------------------------------------

/// The recorded grant: real tokens, their ghosts, and the last response's other fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct Entry {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub placeholder_access: String,
    #[serde(default)]
    pub placeholder_refresh: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub refresh_expires_at: Option<i64>,
    /// Non-token fields of the token responses, merged; `…expires_in` as absolute times.
    #[serde(default)]
    pub response: Map<String, Value>,
    #[serde(default)]
    pub refreshed_at: f64,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub refreshing_since: Option<f64>,
    #[serde(default)]
    pub failed_at: Option<f64>,
}

#[derive(Default, Serialize, Deserialize)]
struct VaultFile {
    entry: Option<Entry>,
}

/// What to do with a refresh carrying the current refresh ghost.
#[derive(Debug, PartialEq)]
pub(crate) enum RefreshDecision {
    Answer(Entry),
    Forward(Entry),
    Gone,
}

/// The vault: one grant per supervisor (one supervisor serves one sandbox).
pub(crate) struct Vault {
    path: Option<PathBuf>,
    entry: Mutex<Option<Entry>>,
    /// Hands a recorded sign-in to the gateway (shared login, PLAN.md part 3).
    submitter: Option<Submitter>,
}

/// What became of a sign-in offered to the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Submitted {
    /// The gateway holds the grant now and refreshes it.
    Accepted,
    /// No attached provider's profile allows a sandbox sign-in.
    Refused,
    /// The gateway could not be asked.
    Unavailable,
}

pub(crate) type Submitter = Box<
    dyn Fn(SubmitProviderSignInRequest) -> Pin<Box<dyn Future<Output = Submitted> + Send>>
        + Send
        + Sync,
>;

pub(crate) fn ghost(kind: &str) -> String {
    let bytes = openshell_crypto::random_bytes::<24>().expect("CSPRNG unavailable");
    format!("{GHOST_PREFIX}-{kind}-{}", hex::encode(bytes))
}

fn is_ghost(token: &str) -> bool {
    token.starts_with(&format!("{GHOST_PREFIX}-oat-"))
        || token.starts_with(&format!("{GHOST_PREFIX}-ort-"))
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn as_i64(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

impl Vault {
    /// A vault kept only in memory (tests).
    pub(crate) fn in_memory() -> Self {
        Self { path: None, entry: Mutex::new(None), submitter: None }
    }

    /// A vault persisted at PATH (created 0600 in a 0700 directory).
    pub(crate) fn at(path: PathBuf) -> Self {
        let entry = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<VaultFile>(&bytes).ok())
            .and_then(|file| file.entry);
        Self { path: Some(path), entry: Mutex::new(entry), submitter: None }
    }

    pub(crate) fn with_submitter(mut self, submitter: Submitter) -> Self {
        self.submitter = Some(submitter);
        self
    }

    /// The gateway took the grant over: forget the real refresh token, so this
    /// supervisor can never refresh upstream. The ghosts and the access token
    /// stay until the provider's token arrives and shared mode takes over.
    pub(crate) fn drop_refresh_token(&self, now: f64) {
        self.with(now, |slot| match slot.as_mut() {
            Some(e) => {
                e.refresh_token = None;
                e.refresh_expires_at = None;
                ((), true)
            }
            None => ((), false),
        });
    }

    fn save(&self, entry: &Option<Entry>) {
        let Some(path) = &self.path else { return };
        let Some(dir) = path.parent() else { return };
        let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
        let tmp = path.with_extension("tmp");
        let body = match serde_json::to_vec(&VaultFile { entry: entry.clone() }) {
            Ok(body) => body,
            Err(_) => return,
        };
        let written = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(&body).and_then(|()| f.sync_all()));
        if written.is_ok() {
            let _ = std::fs::rename(&tmp, path);
        } else {
            tracing::warn!(path = %path.display(), "claude vault: cannot save");
        }
    }

    fn with<R>(&self, now: f64, f: impl FnOnce(&mut Option<Entry>) -> (R, bool)) -> R {
        let mut guard = self.entry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut changed = sweep(&mut guard, now);
        let (result, dirty) = f(&mut guard);
        changed |= dirty;
        if changed {
            self.save(&guard);
        }
        result
    }

    /// The entry, if TOKEN is its access or refresh ghost.
    pub(crate) fn find(&self, token: &str, now: f64) -> Option<Entry> {
        self.with(now, |e| {
            let found = e.as_ref().filter(|e| {
                e.placeholder_access == token || e.placeholder_refresh.as_deref() == Some(token)
            });
            (found.cloned(), false)
        })
    }

    pub(crate) fn current(&self, now: f64) -> Option<Entry> {
        self.with(now, |e| (e.clone(), false))
    }

    /// Keep a token response's real tokens. `refresh` keeps the current entry
    /// (and its ghosts); otherwise (sign-in, adoption) a new entry replaces it.
    pub(crate) fn store(&self, tokens: &Map<String, Value>, refresh: bool, now: f64) -> Option<Entry> {
        let access = tokens.get("access_token")?.as_str()?.to_string();
        Some(self.with(now, |slot| {
            if !refresh || slot.is_none() {
                *slot = Some(Entry { placeholder_access: ghost("oat"), ..Entry::default() });
            }
            let e = slot.as_mut().expect("entry just set");
            let secs = now as i64;
            e.access_token = access;
            if let Some(rt) = tokens.get("refresh_token").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                e.refresh_token = Some(rt.to_string());
                if e.placeholder_refresh.is_none() {
                    e.placeholder_refresh = Some(ghost("ort"));
                }
            }
            if let Some(v) = tokens.get("expires_in").and_then(as_i64) {
                e.expires_at = Some(secs + v);
            }
            if let Some(v) = tokens.get("refresh_token_expires_in").and_then(as_i64) {
                e.refresh_expires_at = Some(secs + v);
            }
            for (k, v) in tokens {
                if TOKEN_FIELDS.contains(&k.as_str()) {
                    continue;
                }
                let v = match (k.ends_with("expires_in"), as_i64(v)) {
                    (true, Some(n)) => Value::from(secs + n),
                    _ => v.clone(),
                };
                e.response.insert(k.clone(), v);
            }
            e.refreshed_at = now;
            e.generation += 1;
            e.refreshing_since = None;
            (e.clone(), true)
        }))
    }

    pub(crate) fn begin_refresh(&self, now: f64) -> RefreshDecision {
        self.with(now, |slot| {
            let Some(e) = slot.as_mut() else { return (RefreshDecision::Gone, false) };
            let fresh = e.expires_at.unwrap_or(0) - now as i64 > REFRESH_MARGIN
                && e.failed_at.unwrap_or(0.0) <= e.refreshed_at;
            let inflight = now - e.refreshing_since.unwrap_or(0.0) < REFRESH_INFLIGHT;
            // Without a real refresh token (handed to the gateway) there is
            // nothing to send upstream.
            if fresh || inflight || e.refresh_token.is_none() {
                return (RefreshDecision::Answer(e.clone()), false);
            }
            e.refreshing_since = Some(now);
            (RefreshDecision::Forward(e.clone()), true)
        })
    }

    /// The upstream refresh failed: the next one may go upstream at once.
    pub(crate) fn end_refresh(&self, now: f64) {
        self.with(now, |slot| match slot.as_mut() {
            Some(e) => (e.refreshing_since.take().map(|_| ()), true),
            None => (None, false),
        });
    }

    /// A request with the access token of GENERATION got a 401. Only the
    /// current generation counts: an older token was revoked by the refresh
    /// that replaced it. Returns whether the grant was marked.
    pub(crate) fn mark_failed(&self, generation: u64, now: f64) -> bool {
        self.with(now, |slot| match slot.as_mut() {
            Some(e) if e.generation == generation => {
                e.failed_at = Some(now);
                (true, true)
            }
            _ => (false, false),
        })
    }

    pub(crate) fn remove(&self, now: f64) {
        self.with(now, |slot| (slot.take().map(|_| ()), true));
    }
}

/// Drop an entry whose refresh token (or, without one, access token) has expired.
fn sweep(slot: &mut Option<Entry>, now: f64) -> bool {
    let expired = slot.as_ref().is_some_and(|e| {
        let until = if e.refresh_token.is_some() { e.refresh_expires_at } else { e.expires_at };
        until.is_some_and(|t| (t as f64) < now)
    });
    if expired {
        *slot = None;
    }
    expired
}

/// A token response for E, as the vault answers a refresh: the recorded
/// fields, the ghosts, and lifetimes counted from now (at least a minute).
pub(crate) fn answer_body(e: &Entry, now: f64) -> Map<String, Value> {
    let now = now as i64;
    let mut body: Map<String, Value> = e
        .response
        .iter()
        .map(|(k, v)| match (k.ends_with("expires_in"), as_i64(v)) {
            (true, Some(t)) => (k.clone(), Value::from((t - now).max(60))),
            _ => (k.clone(), v.clone()),
        })
        .collect();
    body.insert("expires_in".into(), Value::from((e.expires_at.unwrap_or(0) - now).max(60)));
    body.insert("access_token".into(), Value::from(e.placeholder_access.clone()));
    if let Some(rt) = &e.placeholder_refresh {
        body.insert("refresh_token".into(), Value::from(rt.clone()));
    }
    body
}

/// The token response the sandbox gets: E's ghosts in place of real tokens,
/// `id_token` withheld, other fields unchanged.
pub(crate) fn rewrite_tokens(tokens: &Map<String, Value>, e: &Entry) -> Map<String, Value> {
    let mut out = tokens.clone();
    out.remove("id_token");
    if out.contains_key("access_token") {
        out.insert("access_token".into(), Value::from(e.placeholder_access.clone()));
    }
    if out.contains_key("refresh_token") {
        match &e.placeholder_refresh {
            Some(rt) => out.insert("refresh_token".into(), Value::from(rt.clone())),
            None => out.remove("refresh_token"),
        };
    }
    out
}

fn has_tokens(body: &Map<String, Value>) -> bool {
    TOKEN_FIELDS.iter().any(|k| body.get(*k).and_then(Value::as_str).is_some_and(|s| !s.is_empty()))
}

fn vault() -> &'static Vault {
    static VAULT: OnceLock<Vault> = OnceLock::new();
    VAULT.get_or_init(|| {
        let dir = std::env::var(ENV_DIR).unwrap_or_else(|_| DEFAULT_DIR.to_string());
        Vault::at(PathBuf::from(dir).join("vault.json"))
            .with_submitter(Box::new(|request| Box::pin(submit_to_gateway(request))))
    })
}

// ---------------------------------------------------------------------------
// Handing a sign-in to the gateway
// ---------------------------------------------------------------------------

struct GatewayLink {
    gateway: GatewayEndpoint,
    sandbox_id: String,
}

static GATEWAY: OnceLock<GatewayLink> = OnceLock::new();

/// Called once at start-up with this sandbox's gateway access. One supervisor
/// serves one sandbox with the podman driver; the first call wins.
pub(crate) fn set_gateway(gateway: Option<GatewayEndpoint>, sandbox_id: Option<String>) {
    if let (Some(gateway), Some(sandbox_id)) = (gateway, sandbox_id) {
        let _ = GATEWAY.set(GatewayLink { gateway, sandbox_id });
    }
}

/// The submission for E, recorded from a sign-in by CLIENT_ID. None when the
/// grant can't be shared (no refresh token or expiry). `sandbox_id` is filled
/// in by [`submit_to_gateway`]. Carries real tokens: never log it.
pub(crate) fn sign_in_request(e: &Entry, client_id: &str) -> Option<SubmitProviderSignInRequest> {
    let refresh_token = e.refresh_token.clone().filter(|t| !t.is_empty())?;
    let expires_at = e.expires_at?;
    if client_id.is_empty() {
        return None;
    }
    let uuid = |field: &str| {
        e.response
            .get(field)
            .and_then(|v| v.get("uuid"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Some(SubmitProviderSignInRequest {
        sandbox_id: String::new(),
        credential_key: SHARED_KEY.to_string(),
        access_token: e.access_token.clone(),
        expiration_time: openshell_core::time::timestamp_from_millis(expires_at.saturating_mul(1000)).ok(),
        refresh_material: std::collections::HashMap::from([
            ("client_id".to_string(), client_id.to_string()),
            ("refresh_token".to_string(), refresh_token),
        ]),
        account_uuid: uuid("account"),
        organization_uuid: uuid("organization"),
    })
}

async fn submit_to_gateway(mut request: SubmitProviderSignInRequest) -> Submitted {
    let Some(link) = GATEWAY.get() else {
        return Submitted::Unavailable;
    };
    request.sandbox_id.clone_from(&link.sandbox_id);
    let call = openshell_core::grpc_client::submit_provider_sign_in(&link.gateway, request);
    match tokio::time::timeout(SUBMIT_TIMEOUT, call).await {
        Ok(Ok(_provider)) => Submitted::Accepted,
        Ok(Err(status)) => match status.code() {
            tonic::Code::PermissionDenied
            | tonic::Code::FailedPrecondition
            | tonic::Code::InvalidArgument
            | tonic::Code::NotFound
            | tonic::Code::Unimplemented => Submitted::Refused,
            code => {
                tracing::warn!(code = ?code, "claude vault: sign-in not submitted");
                Submitted::Unavailable
            }
        },
        Err(_) => Submitted::Unavailable,
    }
}

/// Offer a just-recorded sign-in to the gateway; on acceptance this supervisor
/// stops being a refresher. Otherwise the sandbox stays in sandbox login.
async fn offer_sign_in(vault: &Vault, entry: &Entry, client_id: &str, ctx: &L7EvalContext, now: f64) {
    let Some(submitter) = &vault.submitter else { return };
    let Some(request) = sign_in_request(entry, client_id) else { return };
    match submitter(request).await {
        Submitted::Accepted => {
            vault.drop_refresh_token(now);
            log(ctx, "sign-in-accepted", "POST", TOKEN_PATH, false);
        }
        Submitted::Refused => log(ctx, "sign-in-kept", "POST", TOKEN_PATH, false),
        Submitted::Unavailable => log(ctx, "sign-in-not-submitted", "POST", TOKEN_PATH, false),
    }
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

/// The request's header lines (request line first) and the body bytes read with them.
fn split_raw(raw: &[u8]) -> (Vec<String>, &[u8]) {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").map_or(raw.len(), |p| p + 4);
    let head = String::from_utf8_lossy(&raw[..end]);
    let lines = head.split("\r\n").filter(|l| !l.is_empty()).map(str::to_string).collect();
    (lines, &raw[end.min(raw.len())..])
}

fn header<'a>(lines: &'a [String], name: &str) -> Option<&'a str> {
    lines.iter().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

async fn read_chunked<R: AsyncBufReadExt + Unpin>(r: &mut R, out: &mut Vec<u8>) -> Result<()> {
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await.into_diagnostic()? == 0 {
            return Err(miette::miette!("chunked body cut off"));
        }
        let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| miette::miette!("bad chunk size"))?;
        if size == 0 {
            // Trailers, then a blank line.
            loop {
                line.clear();
                if r.read_line(&mut line).await.into_diagnostic()? == 0 || line.trim().is_empty() {
                    return Ok(());
                }
            }
        }
        if out.len() + size > MAX_BODY {
            return Err(miette::miette!("body too large"));
        }
        let start = out.len();
        out.resize(start + size, 0);
        r.read_exact(&mut out[start..]).await.into_diagnostic()?;
        line.clear();
        r.read_line(&mut line).await.into_diagnostic()?;
    }
}

/// The whole request body: the bytes read with the header, then the rest from CLIENT.
async fn read_request_body<C: AsyncRead + Unpin>(
    req: &L7Request,
    overflow: &[u8],
    client: &mut C,
) -> Result<Vec<u8>> {
    match req.body_length {
        BodyLength::None => Ok(Vec::new()),
        BodyLength::ContentLength(n) => {
            let n = usize::try_from(n).into_diagnostic()?;
            if n > MAX_BODY {
                return Err(miette::miette!("body too large"));
            }
            let mut body = overflow[..overflow.len().min(n)].to_vec();
            let start = body.len();
            body.resize(n, 0);
            client.read_exact(&mut body[start..]).await.into_diagnostic()?;
            Ok(body)
        }
        BodyLength::Chunked => {
            let mut r = tokio::io::BufReader::new(AsyncReadExt::chain(overflow, client));
            let mut body = Vec::new();
            read_chunked(&mut r, &mut body).await?;
            Ok(body)
        }
    }
}

pub(crate) struct UpstreamResponse {
    pub status: u16,
    pub head: Vec<String>,
    pub body: Vec<u8>,
}

/// Send LINES (request line and headers, minus framing) with BODY, and read the whole response.
async fn round_trip<U: AsyncRead + AsyncWrite + Unpin>(
    upstream: &mut U,
    lines: &[String],
    body: &[u8],
) -> Result<UpstreamResponse> {
    let mut out = String::new();
    out.push_str(&lines[0]);
    out.push_str("\r\n");
    for l in &lines[1..] {
        let name = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection" | "accept-encoding" | "keep-alive") {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    // The vault must read the response: ask for one it can decode.
    out.push_str("Accept-Encoding: identity\r\nConnection: close\r\n");
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    upstream.write_all(out.as_bytes()).await.into_diagnostic()?;
    upstream.write_all(body).await.into_diagnostic()?;
    upstream.flush().await.into_diagnostic()?;

    let mut r = tokio::io::BufReader::new(upstream);
    let mut head = Vec::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await.into_diagnostic()? == 0 {
            return Err(miette::miette!("response cut off"));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            // Skip interim 1xx responses.
            if head.first().is_some_and(|s: &String| s.split(' ').nth(1).is_some_and(|c| c.starts_with('1'))) {
                head.clear();
                continue;
            }
            break;
        }
        head.push(line);
    }
    let status = head
        .first()
        .and_then(|s| s.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| miette::miette!("bad status line"))?;
    let mut body = Vec::new();
    if header(&head, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        read_chunked(&mut r, &mut body).await?;
    } else if let Some(n) = header(&head, "content-length").and_then(|v| v.parse::<usize>().ok()) {
        if n > MAX_BODY {
            return Err(miette::miette!("body too large"));
        }
        body.resize(n, 0);
        r.read_exact(&mut body).await.into_diagnostic()?;
    } else if !(status == 204 || status == 304) {
        (&mut r).take(MAX_BODY as u64).read_to_end(&mut body).await.into_diagnostic()?;
    }
    Ok(UpstreamResponse { status, head, body })
}

/// The response body decoded, or None for an encoding the vault can't read.
fn decoded(resp: &UpstreamResponse) -> Option<Vec<u8>> {
    match header(&resp.head, "content-encoding").map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("" | "identity") => Some(resp.body.clone()),
        Some("gzip" | "x-gzip") => {
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&resp.body[..]), &mut out).ok()?;
            Some(out)
        }
        Some("deflate") => {
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&resp.body[..]), &mut out).ok()?;
            Some(out)
        }
        Some(_) => None,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        502 => "Bad Gateway",
        _ => "",
    }
}

async fn respond<C: AsyncWrite + Unpin>(client: &mut C, status: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    client.write_all(head.as_bytes()).await.into_diagnostic()?;
    client.write_all(body).await.into_diagnostic()?;
    client.flush().await.into_diagnostic()
}

async fn respond_json<C: AsyncWrite + Unpin>(client: &mut C, status: u16, body: &Map<String, Value>) -> Result<()> {
    let bytes = serde_json::to_vec(body).into_diagnostic()?;
    respond(client, status, "application/json", &bytes).await
}

async fn bad_gateway<C: AsyncWrite + Unpin>(client: &mut C) -> Result<()> {
    respond(client, 502, "text/plain", b"claude vault: token response not handled\n").await
}

/// Pass an upstream response on as it came (decoded framing, same body bytes).
async fn pass_through<C: AsyncWrite + Unpin>(client: &mut C, resp: &UpstreamResponse) -> Result<()> {
    let mut out = format!("{}\r\n", resp.head[0]);
    for l in &resp.head[1..] {
        let name = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection" | "keep-alive") {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", resp.body.len()));
    client.write_all(out.as_bytes()).await.into_diagnostic()?;
    client.write_all(&resp.body).await.into_diagnostic()?;
    client.flush().await.into_diagnostic()
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

enum Body {
    Json(Map<String, Value>),
    Form(Vec<(String, String)>),
    Other,
}

impl Body {
    fn parse(lines: &[String], bytes: &[u8]) -> Self {
        let ctype = header(lines, "content-type").unwrap_or("").to_ascii_lowercase();
        if ctype.contains("x-www-form-urlencoded") {
            return Body::Form(
                form_urlencoded::parse(bytes).map(|(k, v)| (k.into_owned(), v.into_owned())).collect(),
            );
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(Value::Object(m)) => Body::Json(m),
            _ => Body::Other,
        }
    }

    fn get(&self, key: &str) -> Option<String> {
        match self {
            Body::Json(m) => m.get(key).and_then(Value::as_str).map(str::to_string),
            Body::Form(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()),
            Body::Other => None,
        }
    }

    fn set(&mut self, key: &str, value: &str) {
        match self {
            Body::Json(m) => {
                m.insert(key.into(), Value::from(value));
            }
            Body::Form(pairs) => {
                for (k, v) in pairs.iter_mut() {
                    if k == key {
                        *v = value.to_string();
                    }
                }
            }
            Body::Other => {}
        }
    }

    fn encode(&self, original: &[u8]) -> Vec<u8> {
        match self {
            Body::Json(m) => serde_json::to_vec(m).unwrap_or_else(|_| original.to_vec()),
            Body::Form(pairs) => form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish()
                .into_bytes(),
            Body::Other => original.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Relay hook
// ---------------------------------------------------------------------------

/// Which real token a forwarded request carries, so a 401 can be matched to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Swapped {
    /// The sandbox's own grant, at this generation.
    Grant(u64),
    /// The gateway's shared token, at this provider revision.
    Shared(u64),
}

/// What the relay does next with a request the vault has seen.
pub(crate) enum Intercept {
    /// Forward as usual. `generation` is set when a real token was swapped in.
    Pass { generation: Option<Swapped> },
    /// The vault answered the request; close the connection.
    Handled,
}

fn enabled() -> bool {
    switch_is_on(std::env::var(ENV_SWITCH).ok().as_deref())
}

/// Provider environment keys the supervisor must keep out of the sandbox's
/// environment: the shared token, when the vault is on.
pub fn hidden_env_keys() -> &'static [&'static str] {
    if enabled() { &[SHARED_KEY] } else { &[] }
}

/// The gateway's shared token, as the supervisor has it now.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SharedToken {
    pub access_token: String,
    pub expires_at_ms: Option<i64>,
    pub revision: u64,
}

fn shared_token(ctx: &L7EvalContext) -> Option<SharedToken> {
    let (access_token, expires_at_ms, revision) = ctx
        .provider_credentials
        .as_ref()?
        .current_secret_for_env_key(SHARED_KEY)?;
    (!access_token.is_empty()).then_some(SharedToken { access_token, expires_at_ms, revision })
}

/// Shared login's ghosts: minted once per supervisor.
fn shared_ghosts() -> &'static (String, String) {
    static GHOSTS: OnceLock<(String, String)> = OnceLock::new();
    GHOSTS.get_or_init(|| (ghost("oat"), ghost("ort")))
}

/// Seconds Claude Code may use the shared token for, from NOW.
pub(crate) fn shared_expires_in(shared: &SharedToken, now: f64) -> i64 {
    shared.expires_at_ms.map_or(SHARED_DEFAULT_EXPIRES_IN, |ms| {
        ((ms - SHARED_EXPIRY_MARGIN_MS) / 1000 - now as i64).max(60)
    })
}

/// The token response shared login answers a refresh or sign-in with.
pub(crate) fn shared_answer(shared: &SharedToken, ghosts: &(String, String), now: f64) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("token_type".into(), Value::from("Bearer"));
    body.insert("access_token".into(), Value::from(ghosts.0.clone()));
    body.insert("refresh_token".into(), Value::from(ghosts.1.clone()));
    body.insert("expires_in".into(), Value::from(shared_expires_in(shared, now)));
    body.insert("scope".into(), Value::from(SHARED_SCOPES));
    body
}

/// Claude Code's `.credentials.json` with shared login's ghosts, as the
/// proxy's `CredentialDeliveryPlugin` writes it (times in milliseconds).
pub(crate) fn shared_credentials_file(shared: &SharedToken, ghosts: &(String, String), now: f64) -> Map<String, Value> {
    let expires_at_ms = (now as i64 + shared_expires_in(shared, now)) * 1000;
    let oauth = serde_json::json!({
        "accessToken": ghosts.0,
        "refreshToken": ghosts.1,
        "expiresAt": expires_at_ms,
        "scopes": SHARED_SCOPES.split(' ').collect::<Vec<_>>(),
    });
    let mut file = Map::new();
    file.insert("claudeAiOauth".into(), oauth);
    file
}

fn oauth_error(error: &str, description: &str) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("error".into(), Value::from(error));
    body.insert("error_description".into(), Value::from(description));
    body
}

pub(crate) fn switch_is_on(value: Option<&str>) -> bool {
    value == Some("on")
}

fn log(ctx: &L7EvalContext, event: &str, method: &str, path: &str, denied: bool) {
    let (action, disposition, severity) = if denied {
        (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium)
    } else {
        (ActionId::Allowed, DispositionId::Allowed, SeverityId::Informational)
    };
    let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(action)
        .disposition(disposition)
        .severity(severity)
        .http_request(HttpRequest::new(method, ctx.ocsf_url(path)))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        // The shorthand log shows the rule but not the message: name the event there.
        .firewall_rule(&format!("claude-vault:{event}"), "l7")
        .message(format!("CLAUDE_VAULT {event} {method} {}:{}{path}", ctx.host, ctx.port))
        .build();
    egress_emit!(event);
}

fn path_of(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// Swap the access ghost in `Authorization: Bearer` / `x-api-key` for the real
/// token. Returns the new header block and the token's generation.
pub(crate) fn swap_headers(lines: &[String], entry: &Entry) -> Option<(Vec<String>, u64)> {
    let mut swapped = false;
    let out = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if i == 0 {
                return l.clone();
            }
            let Some((k, v)) = l.split_once(':') else { return l.clone() };
            let name = k.trim().to_ascii_lowercase();
            let value = v.trim();
            if name == "authorization" {
                if let Some((scheme, token)) = value.split_once(' ') {
                    if scheme.eq_ignore_ascii_case("bearer") && token.trim() == entry.placeholder_access {
                        swapped = true;
                        return format!("{}: {scheme} {}", k.trim(), entry.access_token);
                    }
                }
            } else if name == "x-api-key" && value == entry.placeholder_access {
                swapped = true;
                return format!("{}: {}", k.trim(), entry.access_token);
            }
            l.clone()
        })
        .collect();
    swapped.then_some((out, entry.generation))
}

fn ghosts_in(lines: &[String]) -> bool {
    lines.iter().skip(1).any(|l| l.contains(&format!("{GHOST_PREFIX}-o")))
}

/// See the module docs. Called for each allowed REST request before it is forwarded.
pub(crate) async fn intercept<C, U>(
    req: &mut L7Request,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<Intercept>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    if !enabled() {
        return Ok(Intercept::Pass { generation: None });
    }
    intercept_with(vault(), req, client, upstream, ctx, now_f64()).await
}

pub(crate) async fn intercept_with<C, U>(
    vault: &Vault,
    req: &mut L7Request,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    now: f64,
) -> Result<Intercept>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let path = path_of(&req.target).to_string();
    let method = req.action.clone();
    let (lines, overflow) = split_raw(&req.raw_header);
    let tls_vault_host = ctx.port == 443
        && ctx.request_scheme() == "https"
        && VAULT_HOSTS.contains(&ctx.host.to_ascii_lowercase().as_str());
    if !tls_vault_host {
        if ghosts_in(&lines) {
            log(ctx, "placeholder-elsewhere", &method, &path, false);
        }
        return Ok(Intercept::Pass { generation: None });
    }
    if let Some(shared) = shared_token(ctx) {
        let overflow = overflow.to_vec();
        return intercept_shared(vault, &shared, shared_ghosts(), req, &lines, &overflow, client, upstream, ctx, now)
            .await;
    }
    if ctx.host.eq_ignore_ascii_case(TOKEN_HOST) && method == "POST" && (path == TOKEN_PATH || path == REVOKE_PATH) {
        let overflow = overflow.to_vec();
        let body = match read_request_body(req, &overflow, client).await {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!(error = %e, "claude vault: cannot read token request body");
                return Ok(Intercept::Handled);
            }
        };
        if path == REVOKE_PATH {
            revoke(vault, &lines, body, client, upstream, ctx, now).await?;
        } else {
            token(vault, &lines, body, client, upstream, ctx, now).await?;
        }
        return Ok(Intercept::Handled);
    }
    // Any other request: swap the access ghost for the real token.
    let Some(token) = presented_token(&lines).filter(|t| is_ghost(t)) else {
        return Ok(Intercept::Pass { generation: None });
    };
    let Some(entry) = vault.find(&token, now) else {
        log(ctx, "unknown-placeholder", &method, &path, false);
        return Ok(Intercept::Pass { generation: None });
    };
    let Some((new_lines, generation)) = swap_headers(&lines, &entry) else {
        return Ok(Intercept::Pass { generation: None });
    };
    let overflow = overflow.to_vec();
    set_header_lines(req, &new_lines, &overflow);
    Ok(Intercept::Pass { generation: Some(Swapped::Grant(generation)) })
}

/// The token in `Authorization` (any scheme) or `x-api-key`, if any.
fn presented_token(lines: &[String]) -> Option<String> {
    lines.iter().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        match k.trim().to_ascii_lowercase().as_str() {
            "authorization" => v.trim().split_once(' ').map(|(_, t)| t.trim().to_string()),
            "x-api-key" => Some(v.trim().to_string()),
            _ => None,
        }
    })
}

fn set_header_lines(req: &mut L7Request, lines: &[String], overflow: &[u8]) {
    let mut raw = lines.join("\r\n").into_bytes();
    raw.extend_from_slice(b"\r\n\r\n");
    raw.extend_from_slice(overflow);
    req.raw_header = raw;
}

/// Shared login (see the module docs): the gateway's token, no grant of our own.
#[allow(clippy::too_many_arguments)]
async fn intercept_shared<C, U>(
    vault: &Vault,
    shared: &SharedToken,
    ghosts: &(String, String),
    req: &mut L7Request,
    lines: &[String],
    overflow: &[u8],
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    now: f64,
) -> Result<Intercept>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let path = path_of(&req.target).to_string();
    let method = req.action.clone();
    let token_host = ctx.host.eq_ignore_ascii_case(TOKEN_HOST);
    if token_host && method == "GET" && path == DELIVERY_PATH {
        log(ctx, "credentials-delivered", &method, &path, false);
        respond_json(client, 200, &shared_credentials_file(shared, ghosts, now)).await?;
        return Ok(Intercept::Handled);
    }
    if token_host && method == "POST" && (path == TOKEN_PATH || path == REVOKE_PATH) {
        let raw_body = match read_request_body(req, overflow, client).await {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!(error = %e, "claude vault: cannot read token request body");
                return Ok(Intercept::Handled);
            }
        };
        if path == REVOKE_PATH {
            // The shared grant outlives one sandbox's /logout.
            log(ctx, "revoke-answered", &method, &path, false);
            respond_json(client, 200, &Map::new()).await?;
            return Ok(Intercept::Handled);
        }
        let body = Body::parse(lines, &raw_body);
        let grant = body.get("grant_type").unwrap_or_default();
        let refresh = body.get("refresh_token").unwrap_or_default();
        if grant == "authorization_code" {
            // A real sign-in, as in sandbox login: the code goes to Anthropic, the
            // new grant is recorded and offered to the gateway, which replaces
            // the shared grant if the profile allows it. A bad code gets
            // Anthropic's error, not a false success.
            token(vault, lines, raw_body, client, upstream, ctx, now).await?;
        } else if grant == "refresh_token" && is_ghost(&refresh) {
            log(ctx, "refresh-answered", &method, &path, false);
            respond_json(client, 200, &shared_answer(shared, ghosts, now)).await?;
        } else {
            // A real refresh token (or anything else) would make this sandbox a
            // second refresher of the shared grant.
            log(ctx, "refresh-refused", &method, &path, true);
            let error = oauth_error(
                "invalid_grant",
                "claude vault: shared login; the gateway holds the grant",
            );
            respond_json(client, 400, &error).await?;
        }
        return Ok(Intercept::Handled);
    }
    let Some(token) = presented_token(lines).filter(|t| t.starts_with(&format!("{GHOST_PREFIX}-oat-"))) else {
        return Ok(Intercept::Pass { generation: None });
    };
    let entry = Entry {
        access_token: shared.access_token.clone(),
        placeholder_access: token,
        ..Entry::default()
    };
    let Some((new_lines, _)) = swap_headers(lines, &entry) else {
        return Ok(Intercept::Pass { generation: None });
    };
    set_header_lines(req, &new_lines, overflow);
    Ok(Intercept::Pass { generation: Some(Swapped::Shared(shared.revision)) })
}

/// `POST /v1/oauth/token`: sign-in, refresh, adoption.
async fn token<C, U>(
    vault: &Vault,
    lines: &[String],
    raw_body: Vec<u8>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    now: f64,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut body = Body::parse(lines, &raw_body);
    let grant = body.get("grant_type").unwrap_or_default();
    // How the response's tokens are kept: as a refresh of the entry, as a new
    // entry (sign-in, adoption), or not at all (no tokens expected).
    let mut keep: Option<bool> = None;
    let mut event = "token-forwarded";
    if grant == "refresh_token" {
        let rt = body.get("refresh_token").unwrap_or_default();
        if is_ghost(&rt) {
            match vault.find(&rt, now).filter(|e| e.placeholder_refresh.as_deref() == Some(rt.as_str())) {
                None => log(ctx, "unknown-placeholder", "POST", TOKEN_PATH, false),
                Some(_) => match vault.begin_refresh(now) {
                    RefreshDecision::Answer(e) => {
                        log(ctx, "refresh-answered", "POST", TOKEN_PATH, false);
                        return respond_json(client, 200, &answer_body(&e, now)).await;
                    }
                    RefreshDecision::Forward(e) => {
                        body.set("refresh_token", e.refresh_token.as_deref().unwrap_or_default());
                        keep = Some(true);
                        event = "refresh-upstream";
                    }
                    RefreshDecision::Gone => log(ctx, "unknown-placeholder", "POST", TOKEN_PATH, false),
                },
            }
        } else if !rt.is_empty() {
            keep = Some(false);
            event = "adopt";
        }
    } else if grant == "authorization_code" {
        keep = Some(false);
        event = "sign-in";
    }
    let send = body.encode(&raw_body);
    let resp = match round_trip(upstream, lines, &send).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "claude vault: token request failed upstream");
            if keep == Some(true) {
                vault.end_refresh(now);
            }
            log(ctx, "token-response-cut-off", "POST", TOKEN_PATH, true);
            return bad_gateway(client).await;
        }
    };
    let ok = (200..300).contains(&resp.status);
    let parsed = decoded(&resp).map(|b| serde_json::from_slice::<Value>(&b));
    let json = match &parsed {
        Some(Ok(Value::Object(m))) => Some(m.clone()),
        _ => None,
    };
    if !ok {
        if keep == Some(true) {
            vault.end_refresh(now);
        }
        // An error response carrying tokens is not passed on.
        if json.as_ref().is_some_and(has_tokens) || (parsed.is_none() && !resp.body.is_empty()) {
            log(ctx, "token-response-not-handled", "POST", TOKEN_PATH, true);
            return bad_gateway(client).await;
        }
        log(ctx, &format!("{event}-failed"), "POST", TOKEN_PATH, false);
        return pass_through(client, &resp).await;
    }
    let Some(tokens) = json else {
        if keep == Some(true) {
            vault.end_refresh(now);
        }
        log(ctx, "token-response-not-handled", "POST", TOKEN_PATH, true);
        return bad_gateway(client).await;
    };
    match keep {
        Some(refresh) if tokens.get("access_token").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) => {
            let Some(entry) = vault.store(&tokens, refresh, now) else {
                return bad_gateway(client).await;
            };
            log(ctx, event, "POST", TOKEN_PATH, false);
            if !refresh {
                // A new grant (sign-in or adoption): the gateway may take it over.
                let client_id = body.get("client_id").unwrap_or_default();
                offer_sign_in(vault, &entry, &client_id, ctx, now).await;
            }
            respond_json(client, resp.status, &rewrite_tokens(&tokens, &entry)).await
        }
        _ if has_tokens(&tokens) => {
            if keep == Some(true) {
                vault.end_refresh(now);
            }
            log(ctx, "token-response-not-handled", "POST", TOKEN_PATH, true);
            bad_gateway(client).await
        }
        _ => pass_through(client, &resp).await,
    }
}

/// `POST /v1/oauth/token/revoke`: swap the ghost for the real token, forward, forget on 2xx.
async fn revoke<C, U>(
    vault: &Vault,
    lines: &[String],
    raw_body: Vec<u8>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    now: f64,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut body = Body::parse(lines, &raw_body);
    let token = body.get("token").unwrap_or_default();
    let entry = vault.find(&token, now);
    if let Some(e) = &entry {
        let real = if token == e.placeholder_access {
            e.access_token.clone()
        } else {
            e.refresh_token.clone().unwrap_or_default()
        };
        body.set("token", &real);
    }
    let send = body.encode(&raw_body);
    let (lines, _) = match &entry {
        Some(e) => {
            let swapped = swap_headers(lines, e).map_or_else(|| lines.to_vec(), |(l, _)| l);
            (swapped, ())
        }
        None => (lines.to_vec(), ()),
    };
    let resp = match round_trip(upstream, &lines, &send).await {
        Ok(resp) => resp,
        Err(_) => return bad_gateway(client).await,
    };
    if entry.is_some() && (200..300).contains(&resp.status) {
        vault.remove(now);
        log(ctx, "revoked", "POST", REVOKE_PATH, false);
    }
    pass_through(client, &resp).await
}

// ---------------------------------------------------------------------------
// 401 detection
// ---------------------------------------------------------------------------

/// Wraps the upstream stream while one request is relayed, and keeps the
/// first bytes read: the start of that request's response (its status line,
/// even when split across reads).
pub(crate) struct StatusSniffer<'a, U> {
    inner: &'a mut U,
    head: Option<Vec<u8>>,
}

impl<'a, U> StatusSniffer<'a, U> {
    pub(crate) fn new(inner: &'a mut U, active: bool) -> Self {
        Self { inner, head: active.then(Vec::new) }
    }

    /// The response's status code, if one was seen.
    pub(crate) fn status(&self) -> Option<u16> {
        let head = self.head.as_ref()?;
        let text = std::str::from_utf8(head.get(..12)?).ok()?;
        text.strip_prefix("HTTP/1.")?.get(2..5)?.parse().ok()
    }
}

impl<U: AsyncRead + Unpin> AsyncRead for StatusSniffer<'_, U> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(head)) = (&result, self.head.as_mut()) {
            let need = 12usize.saturating_sub(head.len());
            let got = &buf.filled()[before..];
            head.extend_from_slice(&got[..got.len().min(need)]);
        }
        result
    }
}

impl<U: AsyncWrite + Unpin> AsyncWrite for StatusSniffer<'_, U> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// After a request with a real token: note a 401.
pub(crate) fn after_response(ctx: &L7EvalContext, generation: Swapped, status: Option<u16>, path: &str) {
    if status != Some(401) {
        return;
    }
    match generation {
        Swapped::Grant(generation) => {
            if vault().mark_failed(generation, now_f64()) {
                log(ctx, "401-current-token", "", path, false);
            }
        }
        // Only the gateway refreshes the shared grant: log, and wait for the
        // next revision (THEORY-401.md in the workspace notes).
        Swapped::Shared(revision) => {
            let current = shared_token(ctx).is_some_and(|s| s.revision == revision);
            let event = if current { "401-shared-current" } else { "401-shared-replaced" };
            log(ctx, event, "", path, false);
        }
    }
}

#[cfg(test)]
#[path = "claude_vault_tests.rs"]
mod tests;
