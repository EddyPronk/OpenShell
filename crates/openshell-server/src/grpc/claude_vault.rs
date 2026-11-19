// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Personal patch: the `ClaudeVault` service (`proto/claude_vault.proto`).
//!
//! A sandbox supervisor whose Claude vault recorded a sign-in hands the grant to
//! the gateway, so one sign-in serves every sandbox with the provider ("shared
//! login", PLAN.md part 3). The policy lives in the provider profile: the
//! annotation [`SIGN_IN_ANNOTATION`] names the credential a sandbox may supply.
//!
//! The gateway accepts a submission only from the sandbox's own supervisor, and
//! only when exactly one provider attached to that sandbox has a profile whose
//! annotation names the credential and whose credential refreshes with
//! `oauth2_refresh_token`. It then replaces the grant with the same steps an
//! admin would run: delete the refresh setup, update the credential, configure
//! the refresh. No token value is logged.

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::metadata::ObjectWorkspace;
use openshell_core::proto::claude_vault_server::ClaudeVault;
use openshell_core::proto::{
    ConfigureProviderRefreshRequest, DeleteProviderRefreshRequest, Provider,
    ProviderCredentialRefreshStrategy, Sandbox, SubmitProviderSignInRequest,
    SubmitProviderSignInResponse, UpdateProviderRequest,
};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::ServerState;
use crate::auth::principal::Principal;

/// Profile annotation: the credential a sandbox may supply by signing in.
pub const SIGN_IN_ANNOTATION: &str = "claude-vault.openshell.dev/sign-in";

/// gRPC path prefix of this service, for routing.
pub const CLAUDE_VAULT_PATH_PREFIX: &str = "/openshell.v1.ClaudeVault/";

/// Refresh material keys recorded with the grant (non-secret identity).
const ACCOUNT_UUID: &str = "account_uuid";
const ORGANIZATION_UUID: &str = "organization_uuid";

#[derive(Clone)]
pub struct ClaudeVaultService {
    state: Arc<ServerState>,
}

impl ClaudeVaultService {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ClaudeVault for ClaudeVaultService {
    async fn submit_provider_sign_in(
        &self,
        request: Request<SubmitProviderSignInRequest>,
    ) -> Result<Response<SubmitProviderSignInResponse>, Status> {
        submit_provider_sign_in(&self.state, request).await
    }
}

/// The submission's expiry in epoch milliseconds.
fn expires_at_ms(req: &SubmitProviderSignInRequest) -> Result<i64, Status> {
    let time = req
        .expiration_time
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("expiration_time is required"))?;
    openshell_core::time::timestamp_to_millis(time)
        .map_err(|e| Status::invalid_argument(format!("expiration_time: {e}")))
}

/// Whether a sign-in submission names a usable credential and token.
fn validate(req: &SubmitProviderSignInRequest, now_ms: i64) -> Result<(), Status> {
    if req.sandbox_id.trim().is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if !super::provider::is_valid_env_key(&req.credential_key) {
        return Err(Status::invalid_argument("credential_key must be an environment variable name"));
    }
    if req.access_token.trim().is_empty() {
        return Err(Status::invalid_argument("access_token is required"));
    }
    if expires_at_ms(req)? <= now_ms {
        return Err(Status::invalid_argument("expiration_time must be in the future"));
    }
    if req
        .refresh_material
        .get("refresh_token")
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(Status::invalid_argument("refresh_material.refresh_token is required"));
    }
    Ok(())
}

/// Whether PROFILE lets a sandbox supply CREDENTIAL_KEY: the annotation names it
/// and the credential refreshes with `oauth2_refresh_token`.
pub(crate) fn profile_allows_sign_in(
    profile: &openshell_providers::ProviderTypeProfile,
    credential_key: &str,
) -> bool {
    profile
        .annotations
        .get(SIGN_IN_ANNOTATION)
        .is_some_and(|value| value.trim() == credential_key)
        && profile.credentials.iter().any(|credential| {
            credential.name == credential_key
                && credential.refresh.as_ref().is_some_and(|refresh| {
                    refresh.strategy == ProviderCredentialRefreshStrategy::Oauth2RefreshToken
                })
        })
}

async fn submit_provider_sign_in(
    state: &Arc<ServerState>,
    request: Request<SubmitProviderSignInRequest>,
) -> Result<Response<SubmitProviderSignInResponse>, Status> {
    // Only the sandbox's own supervisor may submit for it.
    match request.extensions().get::<Principal>() {
        Some(Principal::Sandbox(principal)) if principal.sandbox_id == request.get_ref().sandbox_id => {}
        Some(Principal::Anonymous) | None => {
            return Err(Status::unauthenticated("sandbox identity required"));
        }
        Some(_) => return Err(Status::permission_denied("only the sandbox's supervisor may sign in")),
    }
    let req = request.into_inner();
    validate(&req, openshell_core::time::now_ms())?;

    let sandbox = state
        .store
        .get_message::<Sandbox>(&req.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let workspace = sandbox.object_workspace().to_string();
    let attached = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.clone())
        .unwrap_or_default();

    // The policy check: exactly one attached provider whose profile allows it.
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    let mut allowed = Vec::new();
    for name in &attached {
        let Some(provider) = state
            .store
            .get_message_by_name::<Provider>(&workspace, name)
            .await
            .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        else {
            continue;
        };
        let Some(profile) = super::provider::get_provider_type_profile_for_scope(
            &catalog,
            &provider.r#type,
            &provider.profile_workspace,
        ) else {
            continue;
        };
        if profile_allows_sign_in(&profile, &req.credential_key) {
            allowed.push(provider);
        }
    }
    let provider = match allowed.len() {
        1 => allowed.remove(0),
        0 => {
            info!(sandbox_id = %req.sandbox_id, credential_key = %req.credential_key,
                "claude vault: sign-in refused, no attached provider allows it");
            return Err(Status::permission_denied(
                "no attached provider allows a sign-in for this credential",
            ));
        }
        _ => {
            return Err(Status::failed_precondition(
                "more than one attached provider allows a sign-in for this credential",
            ));
        }
    };
    let provider_name = provider
        .metadata
        .as_ref()
        .map(|metadata| metadata.name.clone())
        .unwrap_or_default();

    // Replace the grant: refresh setup off, new token, refresh setup on.
    super::provider::delete_provider_refresh_in_workspace(
        state,
        workspace.clone(),
        DeleteProviderRefreshRequest {
            workspace_scope: None,
            provider: provider_name.clone(),
            credential_key: req.credential_key.clone(),
            allow_missing: true,
            request_id: String::new(),
        },
    )
    .await?;
    let expiration = req
        .expiration_time
        .ok_or_else(|| Status::invalid_argument("expiration_time is required"))?;
    super::provider::update_provider_in_workspace(
        state,
        workspace.clone(),
        UpdateProviderRequest {
            workspace_scope: None,
            provider: Some(Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    name: provider_name.clone(),
                    workspace: workspace.clone(),
                    ..Default::default()
                }),
                credentials: HashMap::from([(req.credential_key.clone(), req.access_token.clone())]),
                ..Default::default()
            }),
            credential_expiration_times: HashMap::from([(req.credential_key.clone(), expiration)]),
            clear_credential_expiration_keys: Vec::new(),
            request_id: String::new(),
        },
    )
    .await?;
    let mut material = req.refresh_material.clone();
    if !req.account_uuid.is_empty() {
        material.insert(ACCOUNT_UUID.to_string(), req.account_uuid.clone());
    }
    if !req.organization_uuid.is_empty() {
        material.insert(ORGANIZATION_UUID.to_string(), req.organization_uuid.clone());
    }
    super::provider::configure_provider_refresh_in_workspace(
        state,
        workspace.clone(),
        ConfigureProviderRefreshRequest {
            workspace_scope: None,
            provider: provider_name.clone(),
            credential_key: req.credential_key.clone(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
            material,
            secret_material_keys: vec!["refresh_token".to_string()],
            expiration_time: Some(expiration),
            request_id: String::new(),
        },
        super::mutation_replay::ordinary::Facts::default(),
    )
    .await?;

    info!(
        sandbox_id = %req.sandbox_id,
        workspace = %workspace,
        provider = %provider_name,
        credential_key = %req.credential_key,
        account_uuid = %req.account_uuid,
        organization_uuid = %req.organization_uuid,
        expires_at_ms = expires_at_ms(&req).unwrap_or_default(),
        "claude vault: sign-in accepted, grant replaced"
    );
    Ok(Response::new(SubmitProviderSignInResponse {
        provider: provider_name,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(annotation: Option<&str>, refresh: Option<&str>) -> openshell_providers::ProviderTypeProfile {
        let annotations = annotation
            .map(|value| format!("annotations:\n  {SIGN_IN_ANNOTATION}: {value}\n"))
            .unwrap_or_default();
        let refresh = refresh
            .map(|strategy| {
                format!(
                    "    refresh:\n      strategy: {strategy}\n      token_url: https://platform.claude.com/v1/oauth/token\n      material:\n        - name: refresh_token\n          secret: true\n"
                )
            })
            .unwrap_or_default();
        let yaml = format!(
            "id: claude-test\n{annotations}display_name: Test\ncredentials:\n  - name: CLAUDE_ACCESS_TOKEN\n    env_vars: [CLAUDE_ACCESS_TOKEN]\n{refresh}endpoints: []\nbinaries: []\n"
        );
        openshell_providers::parse_profile_yaml(&yaml).expect("profile parses")
    }

    #[test]
    fn sign_in_needs_the_annotation_and_an_oauth2_refresh() {
        let key = "CLAUDE_ACCESS_TOKEN";
        assert!(profile_allows_sign_in(&profile(Some(key), Some("oauth2_refresh_token")), key));
        assert!(!profile_allows_sign_in(&profile(None, Some("oauth2_refresh_token")), key));
        assert!(!profile_allows_sign_in(&profile(Some("OTHER"), Some("oauth2_refresh_token")), key));
        assert!(!profile_allows_sign_in(&profile(Some(key), None), key));
        assert!(!profile_allows_sign_in(&profile(Some(key), Some("oauth2_refresh_token")), "OTHER"));
    }

    fn request() -> SubmitProviderSignInRequest {
        SubmitProviderSignInRequest {
            sandbox_id: "sb-1".into(),
            credential_key: "CLAUDE_ACCESS_TOKEN".into(),
            access_token: "token".into(),
            expiration_time: openshell_core::time::timestamp_from_millis(2_000).ok(),
            refresh_material: HashMap::from([("refresh_token".to_string(), "rt".to_string())]),
            account_uuid: String::new(),
            organization_uuid: String::new(),
        }
    }

    #[test]
    fn only_sandbox_supervisors_may_call_it() {
        let path = format!("{CLAUDE_VAULT_PATH_PREFIX}SubmitProviderSignIn");
        let entry = crate::auth::method_authz::lookup(&path).expect("annotated in the descriptor");
        assert_eq!(entry.auth_mode, crate::auth::method_authz::AuthMode::Sandbox);
        assert!(crate::auth::method_authz::is_sandbox_callable(&path));
    }

    #[test]
    fn submission_is_validated() {
        assert!(validate(&request(), 1_000).is_ok());
        assert!(validate(&request(), 3_000).is_err(), "expired");
        let mut r = request();
        r.refresh_material.clear();
        assert!(validate(&r, 1_000).is_err(), "no refresh token");
        let mut r = request();
        r.credential_key = "not a key".into();
        assert!(validate(&r, 1_000).is_err());
        let mut r = request();
        r.access_token = " ".into();
        assert!(validate(&r, 1_000).is_err());
        let mut r = request();
        r.sandbox_id.clear();
        assert!(validate(&r, 1_000).is_err());
        let mut r = request();
        r.expiration_time = None;
        assert!(validate(&r, 1_000).is_err(), "no expiry");
    }
}
