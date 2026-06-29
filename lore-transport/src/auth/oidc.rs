// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! OpenID Connect refresh-token grant.
//!
//! The interactive OIDC login (authorization-code + PKCE) lives in
//! `lore-revision`. This module handles only the silent **refresh** half: given a
//! stored refresh token, obtain a new ID token from the provider's token endpoint
//! so an expired ID token doesn't force an interactive re-login. It is invoked
//! from the transport auth-exchange path (`exchange.rs`) when a stored
//! authentication token has expired and the auth URL uses the `oidc` scheme.

use serde::Deserialize;

use crate::grpc::user_agent;

/// The auth-URL scheme that selects the OIDC flow.
pub const OIDC_SCHEME: &str = "oidc";

#[derive(Debug, Deserialize)]
struct Discovery {
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    id_token: Option<String>,
    refresh_token: Option<String>,
}

/// A refreshed OIDC token pair. Entra rotates refresh tokens, so a new one is
/// usually returned and should replace the stored one.
pub struct RefreshedToken {
    pub id_token: String,
    pub refresh_token: Option<String>,
}

/// Parses `oidc://host/path?client_id=..&scope=..` into `(issuer, client_id, scope)`.
/// Mirrors the parsing in `lore-revision`'s OIDC login.
fn parse_auth_url(auth_url: &str) -> Option<(String, String, String)> {
    let parsed = url::Url::parse(auth_url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let issuer = format!("https://{host}{port}{}", parsed.path())
        .trim_end_matches('/')
        .to_string();

    let mut client_id = None;
    let mut scope = None;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "client_id" => client_id = Some(value.into_owned()),
            "scope" => scope = Some(value.into_owned()),
            _ => {}
        }
    }

    Some((
        issuer,
        client_id?,
        scope.unwrap_or_else(|| "openid profile offline_access".to_string()),
    ))
}

/// Exchanges a refresh token for a new ID token at the provider's token endpoint.
/// Returns `None` on any failure (caller then falls back to requiring re-login).
pub async fn refresh(auth_url: &str, refresh_token: &str) -> Option<RefreshedToken> {
    let (issuer, client_id, scope) = parse_auth_url(auth_url)?;

    let client = reqwest::Client::builder()
        .user_agent(user_agent())
        .build()
        .ok()?;

    // Discover the token endpoint.
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let discovery_body = client
        .get(&discovery_url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()?;
    let discovery: Discovery = serde_json::from_str(&discovery_body).ok()?;

    // Perform the refresh-token grant.
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id.as_str()),
        ("scope", scope.as_str()),
    ];
    let token_body = client
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()?;
    let response: RefreshResponse = serde_json::from_str(&token_body).ok()?;

    Some(RefreshedToken {
        id_token: response.id_token?,
        refresh_token: response.refresh_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth_url_extracts_parts() {
        let (issuer, client_id, scope) = parse_auth_url(
            "oidc://login.microsoftonline.com/tenant/v2.0?client_id=abc&scope=openid%20offline_access",
        )
        .unwrap();
        assert_eq!(issuer, "https://login.microsoftonline.com/tenant/v2.0");
        assert_eq!(client_id, "abc");
        assert_eq!(scope, "openid offline_access");
    }

    #[test]
    fn parse_auth_url_requires_client_id() {
        assert!(parse_auth_url("oidc://login.microsoftonline.com/tenant/v2.0").is_none());
    }
}
