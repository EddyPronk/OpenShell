// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported from agent-mitm-proxy `tests/test_credential_vault.py`.

use super::*;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const NOW: f64 = 1_800_000_000.0;

fn real(n: u32) -> Map<String, Value> {
    let v = serde_json::json!({
        "access_token": format!("sk-ant-oat01-REAL-ACCESS-{n}"),
        "refresh_token": format!("sk-ant-ort01-REAL-REFRESH-{n}"),
        "expires_in": 28800, "refresh_token_expires_in": 2_419_200, "token_type": "Bearer",
        "scope": "user:inference", "token_uuid": "t-1",
        "account": {"uuid": "acc-1", "email_address": "a@example.com"},
        "organization": {"uuid": "org-1", "name": "Org"},
    });
    v.as_object().unwrap().clone()
}

fn ctx(host: &str) -> L7EvalContext {
    L7EvalContext {
        host: host.into(),
        port: 443,
        request_default_port: Some(443),
        policy_name: "claude".into(),
        ..Default::default()
    }
}

fn request(method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> L7Request {
    let mut raw = format!("{method} {target} HTTP/1.1\r\nHost: x\r\n");
    for (k, v) in headers {
        raw.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    raw.push_str("\r\n");
    let mut raw = raw.into_bytes();
    raw.extend_from_slice(body);
    L7Request {
        action: method.into(),
        target: target.into(),
        query_params: HashMap::new(),
        raw_header: raw,
        body_length: if body.is_empty() {
            BodyLength::None
        } else {
            BodyLength::ContentLength(body.len() as u64)
        },
    }
}

fn token_request(fields: Value) -> L7Request {
    let body = serde_json::to_vec(&fields).unwrap();
    request("POST", TOKEN_PATH, &[("Content-Type", "application/json")], &body)
}

fn response(status: &str, body: &Value) -> Vec<u8> {
    let b = serde_json::to_vec(body).unwrap();
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        b.len()
    )
    .into_bytes();
    out.extend_from_slice(&b);
    out
}

/// A fake upstream: reads one request, answers with REPLY, returns what it got.
fn upstream(reply: Option<Vec<u8>>) -> (DuplexStream, tokio::task::JoinHandle<Vec<u8>>) {
    let (ours, mut theirs) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        // Read until the headers and Content-Length body are complete.
        loop {
            let n = theirs.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if got.len() >= end + 4 + len {
                    break;
                }
            }
        }
        if let Some(reply) = reply {
            let _ = theirs.write_all(&reply).await;
        }
        let _ = theirs.shutdown().await;
        got
    });
    (ours, task)
}

struct Run {
    intercept: Intercept,
    client_got: Vec<u8>,
    upstream_got: Option<Vec<u8>>,
}

async fn run(vault: &Vault, host: &str, req: L7Request, reply: Option<Vec<u8>>, now: f64) -> Run {
    run_ctx(vault, &ctx(host), req, reply, now).await
}

async fn run_ctx(vault: &Vault, ctx: &L7EvalContext, mut req: L7Request, reply: Option<Vec<u8>>, now: f64) -> Run {
    let (mut client, mut client_peer) = tokio::io::duplex(1 << 20);
    let (mut up, task) = upstream(reply);
    let intercept = intercept_with(vault, &mut req, &mut client, &mut up, ctx, now)
        .await
        .unwrap();
    drop(client);
    let mut client_got = Vec::new();
    client_peer.read_to_end(&mut client_got).await.unwrap();
    drop(up);
    let upstream_got = task.await.ok().filter(|g| !g.is_empty());
    let raw_header = req.raw_header;
    let _ = raw_header;
    Run { intercept, client_got, upstream_got }
}

fn body_of(resp: &[u8]) -> Map<String, Value> {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    serde_json::from_slice::<Value>(&resp[end..]).unwrap().as_object().unwrap().clone()
}

fn has(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Sign in; returns the ghosts the sandbox got.
async fn sign_in(vault: &Vault) -> (String, String) {
    let req = token_request(serde_json::json!({"grant_type": "authorization_code", "code": "c", "code_verifier": "v"}));
    let r = run(vault, TOKEN_HOST, req, Some(response("200 OK", &Value::Object(real(1)))), NOW).await;
    let got = body_of(&r.client_got);
    (
        got["access_token"].as_str().unwrap().to_string(),
        got["refresh_token"].as_str().unwrap().to_string(),
    )
}

fn refresh_request(token: &str) -> L7Request {
    token_request(serde_json::json!({"grant_type": "refresh_token", "refresh_token": token, "client_id": "id"}))
}

#[tokio::test]
async fn sign_in_hands_out_placeholders_and_keeps_the_tokens() {
    let vault = Vault::in_memory();
    let req = token_request(serde_json::json!({"grant_type": "authorization_code", "code": "c", "code_verifier": "v"}));
    let r = run(&vault, TOKEN_HOST, req, Some(response("200 OK", &Value::Object(real(1)))), NOW).await;
    assert!(matches!(r.intercept, Intercept::Handled));
    let up = r.upstream_got.unwrap();
    assert!(has(&up, "Accept-Encoding: identity"));
    assert!(!has(&r.client_got, "REAL"));
    let got = body_of(&r.client_got);
    assert!(got["access_token"].as_str().unwrap().starts_with("agent-mitm-proxy-oat-"));
    assert!(got["refresh_token"].as_str().unwrap().starts_with("agent-mitm-proxy-ort-"));
    assert_eq!(got["account"]["uuid"], "acc-1");
    assert_eq!(got["expires_in"], 28800);
    let e = vault.current(NOW).unwrap();
    assert_eq!(e.access_token, "sk-ant-oat01-REAL-ACCESS-1");
    assert_eq!(e.refresh_token.as_deref(), Some("sk-ant-ort01-REAL-REFRESH-1"));
    assert!(e.response.contains_key("account"));
    assert!(!e.response.contains_key("access_token") && !e.response.contains_key("refresh_token"));
}

#[tokio::test]
async fn failed_sign_in_passes_through() {
    let vault = Vault::in_memory();
    let req = token_request(serde_json::json!({"grant_type": "authorization_code", "code": "old"}));
    let err = serde_json::json!({"error": "invalid_grant", "error_description": "Invalid 'code' in request."});
    let r = run(&vault, TOKEN_HOST, req, Some(response("400 Bad Request", &err)), NOW).await;
    assert!(r.client_got.starts_with(b"HTTP/1.1 400"));
    assert_eq!(body_of(&r.client_got)["error"], "invalid_grant");
    assert!(vault.current(NOW).is_none());
}

#[tokio::test]
async fn request_gets_the_real_access_token() {
    let vault = Vault::in_memory();
    let (access, _) = sign_in(&vault).await;
    for host in VAULT_HOSTS {
        let mut req = request("GET", "/api/oauth/profile", &[("Authorization", &format!("Bearer {access}"))], b"");
        let (mut c, _peer) = tokio::io::duplex(1024);
        let (mut u, _t) = upstream(None);
        let i = intercept_with(&vault, &mut req, &mut c, &mut u, &ctx(host), NOW).await.unwrap();
        assert!(matches!(i, Intercept::Pass { generation: Some(Swapped::Grant(1)) }));
        assert!(has(&req.raw_header, "Authorization: Bearer sk-ant-oat01-REAL-ACCESS-1"));
        assert!(!has(&req.raw_header, &access));
    }
}

#[tokio::test]
async fn x_api_key_is_swapped_too() {
    let vault = Vault::in_memory();
    let (access, _) = sign_in(&vault).await;
    let mut req = request("POST", "/v1/messages", &[("x-api-key", &access)], b"{}");
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    intercept_with(&vault, &mut req, &mut c, &mut u, &ctx("api.anthropic.com"), NOW).await.unwrap();
    assert!(has(&req.raw_header, "x-api-key: sk-ant-oat01-REAL-ACCESS-1"));
    assert!(req.raw_header.ends_with(b"{}"), "body bytes read with the header are kept");
}

#[tokio::test]
async fn other_hosts_get_the_placeholder() {
    let vault = Vault::in_memory();
    let (access, _) = sign_in(&vault).await;
    let mut req = request("GET", "/", &[("Authorization", &format!("Bearer {access}"))], b"");
    let before = req.raw_header.clone();
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    let i = intercept_with(&vault, &mut req, &mut c, &mut u, &ctx("example.com"), NOW).await.unwrap();
    assert!(matches!(i, Intercept::Pass { generation: None }));
    assert_eq!(req.raw_header, before);
}

#[tokio::test]
async fn plain_http_never_gets_a_token() {
    let vault = Vault::in_memory();
    let (access, _) = sign_in(&vault).await;
    let mut req = request("GET", "/", &[("Authorization", &format!("Bearer {access}"))], b"");
    let before = req.raw_header.clone();
    let mut c80 = ctx("api.anthropic.com");
    c80.port = 80;
    c80.request_default_port = Some(80);
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    intercept_with(&vault, &mut req, &mut c, &mut u, &c80, NOW).await.unwrap();
    assert_eq!(req.raw_header, before);
}

#[tokio::test]
async fn unknown_placeholder_goes_out_unchanged() {
    let vault = Vault::in_memory();
    sign_in(&vault).await;
    let other = ghost("oat");
    let mut req = request("GET", "/", &[("Authorization", &format!("Bearer {other}"))], b"");
    let before = req.raw_header.clone();
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    let i = intercept_with(&vault, &mut req, &mut c, &mut u, &ctx("api.anthropic.com"), NOW).await.unwrap();
    assert!(matches!(i, Intercept::Pass { generation: None }));
    assert_eq!(req.raw_header, before);
}

#[tokio::test]
async fn refresh_answered_by_the_vault_while_the_token_is_fresh() {
    let vault = Vault::in_memory();
    let (access, refresh) = sign_in(&vault).await;
    let later = NOW + 100.0;
    let r = run(&vault, TOKEN_HOST, refresh_request(&refresh), None, later).await;
    assert!(r.upstream_got.is_none(), "nothing upstream");
    assert!(has(&r.client_got.to_ascii_lowercase(), "connection: close"));
    assert!(!has(&r.client_got, "REAL"));
    let got = body_of(&r.client_got);
    assert_eq!(got["access_token"], access.as_str());
    assert_eq!(got["refresh_token"], refresh.as_str());
    assert_eq!(got["expires_in"], 28700);
    assert_eq!(got["refresh_token_expires_in"], 2_419_100);
    assert_eq!(got["account"]["uuid"], "acc-1");
}

#[tokio::test]
async fn one_refresh_upstream_when_the_token_expires() {
    let vault = Vault::in_memory();
    let (access, refresh) = sign_in(&vault).await;
    let later = NOW + 28800.0 - 100.0; // inside REFRESH_MARGIN
    let new = {
        let mut m = real(2);
        m.insert("expires_in".into(), Value::from(28800));
        m
    };
    // Start the upstream refresh but answer a second one while it's in flight.
    assert!(matches!(vault.begin_refresh(later), RefreshDecision::Forward(_)));
    let r2 = run(&vault, TOKEN_HOST, refresh_request(&refresh), None, later + 1.0).await;
    assert!(r2.upstream_got.is_none());
    assert_eq!(body_of(&r2.client_got)["access_token"], access.as_str());
    vault.end_refresh(later);

    let r = run(&vault, TOKEN_HOST, refresh_request(&refresh), Some(response("200 OK", &Value::Object(new))), later).await;
    let up = r.upstream_got.unwrap();
    assert!(has(&up, "sk-ant-ort01-REAL-REFRESH-1") && !has(&up, &refresh));
    let got = body_of(&r.client_got);
    assert_eq!((got["access_token"].as_str(), got["refresh_token"].as_str()), (Some(access.as_str()), Some(refresh.as_str())));
    let e = vault.current(later).unwrap();
    assert!(e.access_token.ends_with("ACCESS-2") && e.refresh_token.unwrap().ends_with("REFRESH-2"));
    assert_eq!(e.generation, 2);
    assert!(e.refreshing_since.is_none());
    // Fresh again: answered locally.
    let r3 = run(&vault, TOKEN_HOST, refresh_request(&refresh), None, later + 60.0).await;
    assert!(r3.upstream_got.is_none());
}

#[tokio::test]
async fn form_refresh_with_a_gzipped_response_without_refresh_token() {
    let vault = Vault::in_memory();
    let (access, refresh) = sign_in(&vault).await;
    let later = NOW + 28800.0 - 100.0;
    let body = format!("grant_type=refresh_token&refresh_token={refresh}");
    let req = request("POST", TOKEN_PATH, &[("Content-Type", "application/x-www-form-urlencoded")], body.as_bytes());
    let mut new = real(3);
    new.remove("refresh_token");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&serde_json::to_vec(&new).unwrap()).unwrap();
    let gz = gz.finish().unwrap();
    let mut reply = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", gz.len()).into_bytes();
    reply.extend_from_slice(&gz);
    let r = run(&vault, TOKEN_HOST, req, Some(reply), later).await;
    assert!(has(&r.upstream_got.unwrap(), "refresh_token=sk-ant-ort01-REAL-REFRESH-1"));
    assert_eq!(body_of(&r.client_got)["access_token"], access.as_str());
    assert!(!has(&r.client_got.to_ascii_lowercase(), "content-encoding"));
    let e = vault.current(later).unwrap();
    assert!(e.access_token.ends_with("ACCESS-3") && e.refresh_token.unwrap().ends_with("REFRESH-1"));
}

#[tokio::test]
async fn failed_refresh_passes_through_and_does_not_block_the_next() {
    let vault = Vault::in_memory();
    let (_, refresh) = sign_in(&vault).await;
    let later = NOW + 28800.0 - 100.0;
    let err = serde_json::json!({"error": "invalid_grant"});
    let r = run(&vault, TOKEN_HOST, refresh_request(&refresh), Some(response("400 Bad Request", &err)), later).await;
    assert!(r.client_got.starts_with(b"HTTP/1.1 400"));
    assert_eq!(body_of(&r.client_got)["error"], "invalid_grant");
    assert!(matches!(vault.begin_refresh(later + 1.0), RefreshDecision::Forward(_)));
}

#[tokio::test]
async fn a_401_with_a_replaced_token_does_not_refresh_again() {
    let vault = Vault::in_memory();
    sign_in(&vault).await;
    vault.store(&real(2), true, NOW + 10.0);
    assert!(!vault.mark_failed(1, NOW + 11.0));
    assert!(matches!(vault.begin_refresh(NOW + 12.0), RefreshDecision::Answer(_)));
}

#[tokio::test]
async fn a_401_with_the_current_token_sends_the_next_refresh_upstream() {
    let vault = Vault::in_memory();
    sign_in(&vault).await;
    assert!(vault.mark_failed(1, NOW + 11.0));
    assert!(matches!(vault.begin_refresh(NOW + 12.0), RefreshDecision::Forward(_)));
}

#[test]
fn status_sniffer_reads_a_split_status_line() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (mut a, mut b) = tokio::io::duplex(64);
        let mut s = StatusSniffer::new(&mut a, true);
        b.write_all(b"HTTP/1.1 4").await.unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).await.unwrap();
        b.write_all(b"01 Unauthorized\r\n").await.unwrap();
        let mut buf = [0u8; 17];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(s.status(), Some(401));
    });
}

#[tokio::test]
async fn refresh_with_a_real_token_is_adopted() {
    let vault = Vault::in_memory();
    let r = run(&vault, TOKEN_HOST, refresh_request("sk-ant-ort01-OLD"), Some(response("200 OK", &Value::Object(real(1)))), NOW).await;
    assert!(has(&r.upstream_got.unwrap(), "sk-ant-ort01-OLD"));
    let got = body_of(&r.client_got);
    assert!(got["access_token"].as_str().unwrap().starts_with("agent-mitm-proxy-oat-"));
    assert_eq!(vault.current(NOW).unwrap().access_token, "sk-ant-oat01-REAL-ACCESS-1");
}

#[tokio::test]
async fn refresh_response_without_account_keeps_it_for_the_vaults_answers() {
    let vault = Vault::in_memory();
    let (_, refresh) = sign_in(&vault).await;
    let mut new = real(2);
    new.remove("account");
    new.remove("organization");
    vault.store(&new, true, NOW + 10.0);
    let r = run(&vault, TOKEN_HOST, refresh_request(&refresh), None, NOW + 20.0).await;
    assert_eq!(body_of(&r.client_got)["account"]["uuid"], "acc-1");
}

#[tokio::test]
async fn entries_with_an_expired_refresh_token_are_forgotten() {
    let vault = Vault::in_memory();
    sign_in(&vault).await;
    assert!(vault.current(NOW + 2_419_201.0).is_none());
}

#[tokio::test]
async fn revoke_swaps_and_removes_the_entry() {
    let vault = Vault::in_memory();
    let (_, refresh) = sign_in(&vault).await;
    let body = serde_json::to_vec(&serde_json::json!({"token": refresh, "client_id": "id"})).unwrap();
    let req = request("POST", REVOKE_PATH, &[("Content-Type", "application/json")], &body);
    let r = run(&vault, TOKEN_HOST, req, Some(response("200 OK", &serde_json::json!({}))), NOW).await;
    let up = r.upstream_got.unwrap();
    assert!(has(&up, "sk-ant-ort01-REAL-REFRESH-1") && !has(&up, &refresh));
    assert!(vault.current(NOW).is_none());
}

#[tokio::test]
async fn id_token_is_withheld() {
    let vault = Vault::in_memory();
    let mut tokens = real(1);
    tokens.insert("id_token".into(), Value::from("eyJ.secret.jwt"));
    let req = token_request(serde_json::json!({"grant_type": "authorization_code", "code": "c"}));
    let r = run(&vault, TOKEN_HOST, req, Some(response("200 OK", &Value::Object(tokens))), NOW).await;
    assert!(!has(&r.client_got, "id_token") && !has(&r.client_got, "secret"));
}

#[tokio::test]
async fn token_response_the_vault_cant_handle_is_not_passed_on() {
    for reply in [
        b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\nxxxx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nnojson".to_vec(),
        response("400 Bad Request", &serde_json::json!({"error": "x", "refresh_token": "sk-ant-ort01-REAL"})),
    ] {
        let vault = Vault::in_memory();
        let req = token_request(serde_json::json!({"grant_type": "authorization_code", "code": "c"}));
        let r = run(&vault, TOKEN_HOST, req, Some(reply), NOW).await;
        assert!(r.client_got.starts_with(b"HTTP/1.1 502"), "{}", String::from_utf8_lossy(&r.client_got));
        assert!(!has(&r.client_got, "REAL"));
    }
}

#[tokio::test]
async fn token_response_cut_off_upstream_gets_the_client_a_502() {
    let vault = Vault::in_memory();
    let req = token_request(serde_json::json!({"grant_type": "authorization_code", "code": "c"}));
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{\"access_token\":\"sk-ant-oat01-REAL".to_vec();
    let r = run(&vault, TOKEN_HOST, req, Some(reply), NOW).await;
    assert!(r.client_got.starts_with(b"HTTP/1.1 502"));
    assert!(!has(&r.client_got, "REAL"));
}

#[tokio::test]
async fn vault_file_is_private_and_survives_reload() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v").join("vault.json");
    let vault = Vault::at(path.clone());
    let (access, _) = sign_in(&vault).await;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dmode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700);
    let again = Vault::at(path);
    assert_eq!(again.find(&access, NOW).unwrap().access_token, "sk-ant-oat01-REAL-ACCESS-1");
}

#[test]
fn switched_on_only_by_on() {
    assert!(switch_is_on(Some("on")));
    for value in [None, Some(""), Some("off"), Some("1"), Some("ON")] {
        assert!(!switch_is_on(value), "{value:?}");
    }
}

#[tokio::test]
async fn sign_in_replaces_the_earlier_grant() {
    let vault = Vault::in_memory();
    let (first, _) = sign_in(&vault).await;
    let (second, _) = sign_in(&vault).await;
    assert_ne!(first, second);
    assert!(vault.find(&first, NOW).is_none());
}

// ---------------------------------------------------------------------------
// Shared login
// ---------------------------------------------------------------------------

use openshell_core::provider_credentials::ProviderCredentialState;

/// The gateway's token expires 8 h after NOW.
const SHARED_EXPIRES_AT_MS: i64 = (NOW as i64 + 28_800) * 1000;

fn shared_state(token: &str, revision: u64) -> ProviderCredentialState {
    let state = ProviderCredentialState::from_environment(
        revision,
        HashMap::from([(SHARED_KEY.to_string(), token.to_string())]),
        HashMap::from([(SHARED_KEY.to_string(), SHARED_EXPIRES_AT_MS)]),
        HashMap::new(),
    );
    state.remove_env_key(SHARED_KEY);
    state
}

fn shared_ctx(host: &str, state: &ProviderCredentialState) -> L7EvalContext {
    let mut c = ctx(host);
    c.provider_credentials = Some(state.clone());
    c
}

#[tokio::test]
async fn shared_any_access_ghost_gets_the_current_shared_token() {
    let vault = Vault::in_memory();
    let state = shared_state("sk-ant-oat01-SHARED-1", 7);
    let access = ghost("oat");
    for host in VAULT_HOSTS {
        let mut req = request("POST", "/v1/messages", &[("Authorization", &format!("Bearer {access}"))], b"{}");
        let (mut c, _peer) = tokio::io::duplex(1024);
        let (mut u, _t) = upstream(None);
        let i = intercept_with(&vault, &mut req, &mut c, &mut u, &shared_ctx(host, &state), NOW).await.unwrap();
        assert!(matches!(i, Intercept::Pass { generation: Some(Swapped::Shared(7)) }));
        assert!(has(&req.raw_header, "Authorization: Bearer sk-ant-oat01-SHARED-1"));
        assert!(req.raw_header.ends_with(b"{}"));
    }
}

#[tokio::test]
async fn shared_swap_follows_a_new_revision() {
    let vault = Vault::in_memory();
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    state.install_environment(
        2,
        HashMap::from([(SHARED_KEY.to_string(), "sk-ant-oat01-SHARED-2".to_string())]),
        HashMap::new(),
        HashMap::new(),
    );
    let access = ghost("oat");
    let mut req = request("GET", "/api/oauth/profile", &[("Authorization", &format!("Bearer {access}"))], b"");
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    let i = intercept_with(&vault, &mut req, &mut c, &mut u, &shared_ctx("api.anthropic.com", &state), NOW)
        .await
        .unwrap();
    assert!(matches!(i, Intercept::Pass { generation: Some(Swapped::Shared(2)) }));
    assert!(has(&req.raw_header, "Bearer sk-ant-oat01-SHARED-2"));
    assert!(!has(&req.raw_header, "SHARED-1"));
}

#[tokio::test]
async fn shared_wins_over_a_sandbox_grant() {
    let vault = Vault::in_memory();
    let (access, _) = sign_in(&vault).await;
    let state = shared_state("sk-ant-oat01-SHARED-1", 3);
    let mut req = request("GET", "/", &[("Authorization", &format!("Bearer {access}"))], b"");
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    intercept_with(&vault, &mut req, &mut c, &mut u, &shared_ctx("api.anthropic.com", &state), NOW).await.unwrap();
    assert!(has(&req.raw_header, "SHARED-1"));
    assert!(!has(&req.raw_header, "REAL-ACCESS"));
}

#[tokio::test]
async fn shared_other_hosts_and_refresh_ghosts_get_nothing() {
    let vault = Vault::in_memory();
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    let access = ghost("oat");
    let mut req = request("GET", "/", &[("Authorization", &format!("Bearer {access}"))], b"");
    let before = req.raw_header.clone();
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    let i = intercept_with(&vault, &mut req, &mut c, &mut u, &shared_ctx("example.com", &state), NOW).await.unwrap();
    assert!(matches!(i, Intercept::Pass { generation: None }));
    assert_eq!(req.raw_header, before);

    let refresh = ghost("ort");
    let mut req = request("GET", "/", &[("Authorization", &format!("Bearer {refresh}"))], b"");
    let before = req.raw_header.clone();
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    intercept_with(&vault, &mut req, &mut c, &mut u, &shared_ctx("api.anthropic.com", &state), NOW).await.unwrap();
    assert_eq!(req.raw_header, before);
}

#[tokio::test]
async fn shared_refresh_is_answered_with_the_gateways_expiry() {
    let vault = Vault::in_memory();
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    let r = run_ctx(&vault, &shared_ctx(TOKEN_HOST, &state), refresh_request(&ghost("ort")), None, NOW).await;
    assert!(matches!(r.intercept, Intercept::Handled));
    assert!(r.upstream_got.is_none(), "never forwarded");
    assert!(r.client_got.starts_with(b"HTTP/1.1 200"));
    assert!(!has(&r.client_got, "SHARED"));
    let got = body_of(&r.client_got);
    assert!(got["access_token"].as_str().unwrap().starts_with("agent-mitm-proxy-oat-"));
    assert!(got["refresh_token"].as_str().unwrap().starts_with("agent-mitm-proxy-ort-"));
    assert_eq!(got["expires_in"], 28_800 - 60);
    assert_eq!(got["token_type"], "Bearer");
}

#[tokio::test]
async fn shared_refresh_with_a_real_token_is_refused() {
    let vault = Vault::in_memory();
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    let req = refresh_request("sk-ant-ort01-SOMEONES-REAL-REFRESH");
    let r = run_ctx(&vault, &shared_ctx(TOKEN_HOST, &state), req, None, NOW).await;
    assert!(r.upstream_got.is_none(), "never forwarded");
    assert!(r.client_got.starts_with(b"HTTP/1.1 400"));
    assert_eq!(body_of(&r.client_got)["error"], "invalid_grant");
    assert!(vault.current(NOW).is_none(), "not adopted");
}

#[tokio::test]
async fn shared_sign_in_goes_upstream_and_replaces_the_grant() {
    let (vault, seen) = vault_with_gateway(Submitted::Accepted);
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    let reply = Some(response("200 OK", &Value::Object(real(1))));
    let r = run_ctx(&vault, &shared_ctx(TOKEN_HOST, &state), sign_in_request_with_client(), reply, NOW).await;
    assert!(r.upstream_got.is_some(), "the code goes to Anthropic");
    assert!(r.client_got.starts_with(b"HTTP/1.1 200"));
    assert!(!has(&r.client_got, "REAL"));
    assert!(body_of(&r.client_got)["access_token"].as_str().unwrap().starts_with("agent-mitm-proxy-oat-"));
    // Offered to the gateway, which takes it over; no refresher stays here.
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(seen.lock().unwrap()[0].access_token, "sk-ant-oat01-REAL-ACCESS-1");
    assert_eq!(vault.current(NOW).unwrap().refresh_token, None);
}

#[tokio::test]
async fn shared_sign_in_with_a_bad_code_gets_anthropics_error() {
    let (vault, seen) = vault_with_gateway(Submitted::Accepted);
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    let err = serde_json::json!({"error": "invalid_grant", "error_description": "Invalid 'code' in request."});
    let reply = Some(response("400 Bad Request", &err));
    let r = run_ctx(&vault, &shared_ctx(TOKEN_HOST, &state), sign_in_request_with_client(), reply, NOW).await;
    assert!(r.client_got.starts_with(b"HTTP/1.1 400"), "no false success");
    assert_eq!(body_of(&r.client_got)["error"], "invalid_grant");
    assert!(seen.lock().unwrap().is_empty(), "nothing to offer");
    assert!(vault.current(NOW).is_none());
}

#[tokio::test]
async fn shared_logout_is_answered_locally() {
    let vault = Vault::in_memory();
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    let body = serde_json::to_vec(&serde_json::json!({"token": ghost("ort"), "client_id": "id"})).unwrap();
    let req = request("POST", REVOKE_PATH, &[("Content-Type", "application/json")], &body);
    let r = run_ctx(&vault, &shared_ctx(TOKEN_HOST, &state), req, None, NOW).await;
    assert!(matches!(r.intercept, Intercept::Handled));
    assert!(r.upstream_got.is_none(), "the shared grant is not revoked");
    assert!(r.client_got.starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn shared_credentials_file_is_delivered_with_ghosts() {
    let vault = Vault::in_memory();
    let state = shared_state("sk-ant-oat01-SHARED-1", 1);
    let req = request("GET", DELIVERY_PATH, &[], b"");
    let r = run_ctx(&vault, &shared_ctx(TOKEN_HOST, &state), req, None, NOW).await;
    assert!(r.upstream_got.is_none());
    assert!(!has(&r.client_got, "SHARED"));
    let file = body_of(&r.client_got);
    let oauth = &file["claudeAiOauth"];
    assert!(oauth["accessToken"].as_str().unwrap().starts_with("agent-mitm-proxy-oat-"));
    assert!(oauth["refreshToken"].as_str().unwrap().starts_with("agent-mitm-proxy-ort-"));
    assert_eq!(oauth["expiresAt"], SHARED_EXPIRES_AT_MS - 60_000);
    assert!(oauth["scopes"].as_array().unwrap().iter().any(|s| s == "user:inference"));
}

#[tokio::test]
async fn without_the_shared_provider_delivery_is_not_answered() {
    let vault = Vault::in_memory();
    let mut req = request("GET", DELIVERY_PATH, &[], b"");
    let (mut c, _peer) = tokio::io::duplex(1024);
    let (mut u, _t) = upstream(None);
    let i = intercept_with(&vault, &mut req, &mut c, &mut u, &ctx(TOKEN_HOST), NOW).await.unwrap();
    assert!(matches!(i, Intercept::Pass { generation: None }));
}

#[test]
fn shared_expiry_without_a_gateway_expiry_is_an_hour() {
    let shared = SharedToken { access_token: "t".into(), expires_at_ms: None, revision: 1 };
    assert_eq!(shared_expires_in(&shared, NOW), 3600);
    let soon = SharedToken { expires_at_ms: Some(NOW as i64 * 1000 + 10_000), ..shared };
    assert_eq!(shared_expires_in(&soon, NOW), 60, "at least a minute");
}

// ---------------------------------------------------------------------------
// Handing a sign-in to the gateway
// ---------------------------------------------------------------------------

type Seen = std::sync::Arc<Mutex<Vec<SubmitProviderSignInRequest>>>;

/// A vault whose gateway answers every submission with OUTCOME.
fn vault_with_gateway(outcome: Submitted) -> (Vault, Seen) {
    let seen: Seen = std::sync::Arc::default();
    let record = seen.clone();
    let vault = Vault::in_memory().with_submitter(Box::new(move |request| {
        record.lock().unwrap().push(request);
        Box::pin(async move { outcome })
    }));
    (vault, seen)
}

fn sign_in_request_with_client() -> L7Request {
    token_request(serde_json::json!({
        "grant_type": "authorization_code", "code": "c", "code_verifier": "v", "client_id": "client-1"
    }))
}

#[tokio::test]
async fn accepted_sign_in_goes_to_the_gateway_and_the_refresh_token_is_dropped() {
    let (vault, seen) = vault_with_gateway(Submitted::Accepted);
    let reply = Some(response("200 OK", &Value::Object(real(1))));
    let r = run(&vault, TOKEN_HOST, sign_in_request_with_client(), reply, NOW).await;

    // Claude Code still gets ghosts only.
    assert!(!has(&r.client_got, "REAL"));
    let got = body_of(&r.client_got);
    let refresh_ghost = got["refresh_token"].as_str().unwrap().to_string();
    assert!(refresh_ghost.starts_with("agent-mitm-proxy-ort-"));

    // The gateway got the real grant and its identity, without the email.
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let sent = &seen[0];
        assert_eq!(sent.credential_key, SHARED_KEY);
        assert_eq!(sent.access_token, "sk-ant-oat01-REAL-ACCESS-1");
        assert_eq!(sent.refresh_material["refresh_token"], "sk-ant-ort01-REAL-REFRESH-1");
        assert_eq!(sent.refresh_material["client_id"], "client-1");
        assert_eq!(sent.refresh_material.len(), 2, "nothing else, so no email");
        assert_eq!(sent.account_uuid, "acc-1");
        assert_eq!(sent.organization_uuid, "org-1");
        let expires_ms =
            openshell_core::time::timestamp_to_millis(sent.expiration_time.as_ref().unwrap()).unwrap();
        assert_eq!(expires_ms, (NOW as i64 + 28_800) * 1000);
    }

    // This supervisor is no refresher any more, even after the token expired.
    let e = vault.current(NOW).unwrap();
    assert_eq!(e.refresh_token, None);
    assert_eq!(e.access_token, "sk-ant-oat01-REAL-ACCESS-1", "kept until the provider's token arrives");
    let late = NOW + 28_700.0;
    let r = run(&vault, TOKEN_HOST, refresh_request(&refresh_ghost), None, late).await;
    assert!(r.upstream_got.is_none(), "never refreshes upstream");
    assert!(r.client_got.starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn refused_or_unreachable_gateway_keeps_sandbox_login() {
    for outcome in [Submitted::Refused, Submitted::Unavailable] {
        let (vault, seen) = vault_with_gateway(outcome);
        let reply = Some(response("200 OK", &Value::Object(real(1))));
        let r = run(&vault, TOKEN_HOST, sign_in_request_with_client(), reply, NOW).await;
        assert!(r.client_got.starts_with(b"HTTP/1.1 200"));
        assert_eq!(seen.lock().unwrap().len(), 1);
        let e = vault.current(NOW).unwrap();
        assert_eq!(e.refresh_token.as_deref(), Some("sk-ant-ort01-REAL-REFRESH-1"), "{outcome:?}");
    }
}

#[tokio::test]
async fn refreshes_and_failed_sign_ins_are_not_submitted() {
    let (vault, seen) = vault_with_gateway(Submitted::Refused);
    let err = serde_json::json!({"error": "invalid_grant"});
    run(&vault, TOKEN_HOST, sign_in_request_with_client(), Some(response("400 Bad Request", &err)), NOW).await;
    assert!(seen.lock().unwrap().is_empty(), "failed sign-in");

    let reply = Some(response("200 OK", &Value::Object(real(1))));
    let r = run(&vault, TOKEN_HOST, sign_in_request_with_client(), reply, NOW).await;
    let refresh_ghost = body_of(&r.client_got)["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(seen.lock().unwrap().len(), 1);

    // An upstream refresh of the sandbox's own grant is not a new sign-in.
    let late = NOW + 28_700.0;
    let reply = Some(response("200 OK", &Value::Object(real(2))));
    let r = run(&vault, TOKEN_HOST, refresh_request(&refresh_ghost), reply, late).await;
    assert!(r.upstream_got.is_some());
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn a_grant_without_refresh_token_expiry_or_client_is_not_submitted() {
    let full = Entry {
        access_token: "a".into(),
        refresh_token: Some("r".into()),
        expires_at: Some(NOW as i64 + 100),
        ..Entry::default()
    };
    assert!(sign_in_request(&full, "client-1").is_some());
    assert!(sign_in_request(&full, "").is_none());
    assert!(sign_in_request(&Entry { refresh_token: None, ..full.clone() }, "client-1").is_none());
    assert!(sign_in_request(&Entry { expires_at: None, ..full }, "client-1").is_none());
}
