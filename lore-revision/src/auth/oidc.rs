// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! OpenID Connect authorization-code + PKCE login.
//!
//! Used for external identity providers (e.g. Microsoft Entra ID) that do not
//! implement Lore's UCS Auth API. The server advertises an `oidc://` auth URL via
//! its environment endpoint; this module performs a standard browser-based
//! authorization-code flow with PKCE, captures the redirect on a loopback
//! listener, exchanges the code for an ID token at the provider's token endpoint,
//! and stores that token bound to the Lore server we are logging in to.
//!
//! The advertised auth URL carries the provider details as query parameters, e.g.
//! `oidc://login.microsoftonline.com/<tenant>/v2.0?client_id=<id>&scope=openid%20profile`.
//! The issuer is the same URL with the scheme rewritten to `https` and the query
//! stripped.

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::prelude::Engine as _;
use lore_credential::UserInfo;
use lore_credential::domain_from_url_or_url;
use lore_credential::token_store;
use lore_credential::user_info_from_token;
use lore_error_set::prelude::*;
use rand::Rng;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

use crate::auth::LoreAuthUrlEventData;
use crate::auth::login::InteractiveLoginError;
use crate::event;
use crate::lore_debug;

/// The scheme that selects this OIDC login flow in an advertised auth URL.
pub const OIDC_SCHEME: &str = "oidc";

/// Characters permitted in a PKCE `code_verifier` (RFC 7636 §4.1 unreserved set).
const VERIFIER_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    #[allow(dead_code)]
    refresh_token: Option<String>,
}

/// Provider parameters parsed out of an advertised `oidc://` auth URL.
struct OidcConfig {
    /// HTTPS issuer URL (scheme rewritten, query stripped).
    issuer: String,
    client_id: String,
    scope: String,
}

/// Parses an advertised `oidc://host/path?client_id=..&scope=..` auth URL.
fn parse_auth_url(auth_url: &str) -> Result<OidcConfig, InteractiveLoginError> {
    let parsed = Url::parse(auth_url).internal("parsing oidc auth URL")?;

    let host = parsed
        .host_str()
        .ok_or_else(|| InteractiveLoginError::internal("oidc auth URL has no host"))?;
    let port = parsed
        .port()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    // Issuer is the same URL over https, without the query string.
    let issuer = format!("https://{host}{port}{}", parsed.path()).trim_end_matches('/').to_string();

    let mut client_id = None;
    let mut scope = None;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "client_id" => client_id = Some(value.into_owned()),
            "scope" => scope = Some(value.into_owned()),
            _ => {}
        }
    }

    let client_id = client_id.ok_or_else(|| {
        InteractiveLoginError::internal("oidc auth URL is missing the `client_id` parameter")
    })?;
    // Default to the minimal OIDC scopes needed for an ID token with profile claims.
    let scope = scope.unwrap_or_else(|| "openid profile".to_string());

    Ok(OidcConfig {
        issuer,
        client_id,
        scope,
    })
}

/// Generates a PKCE `code_verifier` and its S256 `code_challenge`.
fn generate_pkce() -> (String, String) {
    let mut rng = rand::rng();
    let verifier: String = (0..64)
        .map(|_| {
            let idx = rng.random_range(0..VERIFIER_ALPHABET.len());
            VERIFIER_ALPHABET[idx] as char
        })
        .collect();
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

/// Computes the PKCE S256 challenge: base64url(SHA-256(verifier)), no padding.
fn pkce_challenge(verifier: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    BASE64_URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Builds the provider authorization URL for the auth-code + PKCE flow.
fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> Result<String, InteractiveLoginError> {
    let mut url = Url::parse(authorization_endpoint).internal("parsing authorization endpoint")?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_mode", "query")
        .append_pair("scope", scope)
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

/// Extracts the `code` and `state` query parameters from a captured redirect
/// request line (`GET /?code=..&state=.. HTTP/1.1`).
fn parse_redirect_request(request: &str) -> Option<(String, String)> {
    let path = request.split_whitespace().nth(1)?;
    // Reconstruct an absolute URL so we can reuse the query parser.
    let url = Url::parse(&format!("http://127.0.0.1{path}")).ok()?;
    let mut code = None;
    let mut state = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            _ => {}
        }
    }
    Some((code?, state?))
}

/// Waits for the provider to redirect back to the loopback listener and returns
/// the authorization code, validating the `state` round-trips.
async fn await_redirect(
    listener: &TcpListener,
    expected_state: &str,
) -> Result<String, InteractiveLoginError> {
    // Browsers may open incidental connections (e.g. favicon); accept until we
    // see a request that actually carries the authorization parameters.
    for _ in 0..10 {
        let (mut stream, _) = listener
            .accept()
            .await
            .internal("accepting OIDC redirect connection")?;

        let mut buf = vec![0u8; 8192];
        let n = stream
            .read(&mut buf)
            .await
            .internal("reading OIDC redirect request")?;
        let request = String::from_utf8_lossy(&buf[..n]);

        let parsed = request.lines().next().and_then(parse_redirect_request);

        let (body, result) = match &parsed {
            Some((code, state)) if state == expected_state => (
                "<html><body><h2>Sign-in complete</h2>You may close this tab and return to the terminal.</body></html>",
                Some(Ok(code.clone())),
            ),
            Some(_) => (
                "<html><body><h2>Sign-in failed</h2>State mismatch; please try again.</body></html>",
                Some(Err(InteractiveLoginError::internal(
                    "OIDC redirect state mismatch (possible CSRF)",
                ))),
            ),
            None => (
                "<html><body>Waiting for sign-in...</body></html>",
                None,
            ),
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;

        if let Some(result) = result {
            return result;
        }
    }

    Err(InteractiveLoginError::internal(
        "gave up waiting for the OIDC redirect",
    ))
}

/// Performs an OIDC authorization-code + PKCE login against the provider in
/// `auth_url`, stores the resulting ID token bound to `remote_url`, and returns
/// the authenticated user's info.
pub async fn interactive_login(
    auth_url: &str,
    remote_url: &Url,
    no_browser: bool,
) -> Result<UserInfo, InteractiveLoginError> {
    let config = parse_auth_url(auth_url)?;
    lore_debug!(
        "OIDC login: issuer={} client_id={}",
        config.issuer,
        config.client_id
    );

    let client = reqwest::Client::builder()
        .user_agent(lore_transport::grpc::user_agent())
        .build()
        .internal("building OIDC HTTP client")?;

    // 1. Discover the provider's endpoints.
    let discovery_url = format!("{}/.well-known/openid-configuration", config.issuer);
    let discovery_body = client
        .get(&discovery_url)
        .send()
        .await
        .internal("fetching OIDC discovery document")?
        .error_for_status()
        .internal("OIDC discovery document request failed")?
        .text()
        .await
        .internal("reading OIDC discovery document")?;
    let discovery: OidcDiscovery =
        serde_json::from_str(&discovery_body).internal("parsing OIDC discovery document")?;

    // 2. PKCE + CSRF/replay parameters.
    let (verifier, challenge) = generate_pkce();
    let state = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();

    // 3. Loopback listener for the redirect (dynamic port).
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .internal("binding loopback listener for OIDC redirect")?;
    let port = listener
        .local_addr()
        .internal("reading loopback listener address")?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/");

    // 4. Open the browser (or surface the URL for headless logins).
    let authorize_url = build_authorize_url(
        &discovery.authorization_endpoint,
        &config.client_id,
        &redirect_uri,
        &config.scope,
        &state,
        &nonce,
        &challenge,
    )?;

    if no_browser {
        event::LoreEvent::AuthUrl(LoreAuthUrlEventData {
            url: authorize_url.clone().into(),
        })
        .send();
    } else {
        open::that(authorize_url.as_str()).internal("opening OIDC authorization URL")?;
    }

    // 5. Capture the authorization code from the redirect.
    let code = await_redirect(&listener, &state).await?;
    lore_debug!("OIDC redirect captured, exchanging code for token");

    // 6. Exchange the code for tokens.
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", config.client_id.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let token_body = client
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .internal("exchanging OIDC authorization code")?
        .error_for_status()
        .internal("OIDC token endpoint returned an error")?
        .text()
        .await
        .internal("reading OIDC token response")?;
    let token_response: TokenResponse =
        serde_json::from_str(&token_body).internal("parsing OIDC token response")?;

    let id_token = token_response
        .id_token
        .ok_or_else(|| InteractiveLoginError::internal("OIDC token response had no id_token"))?;

    // 7. Store the token bound to the Lore server we are logging in to. The token's
    // own `aud`/`iss` reference the IdP, not the Lore server, so we bind it to the
    // remote domain explicitly (we trust it because the server advertised this
    // auth URL). `store_user_token` also records the auth endpoint domain.
    let user_info = user_info_from_token(id_token.clone())
        .ok_or_else(|| InteractiveLoginError::internal("OIDC id_token could not be decoded"))?;
    let remote_domain = domain_from_url_or_url(remote_url);

    token_store::store_user_token(
        auth_url,
        user_info.id.as_str(),
        &id_token,
        vec![remote_domain],
    )
    .await
    .forward::<InteractiveLoginError>("storing OIDC token")?;

    lore_debug!("OIDC login successful for {}", user_info.id);
    Ok(user_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_verifier_has_valid_length_and_alphabet() {
        let (verifier, challenge) = generate_pkce();
        assert!((43..=128).contains(&verifier.len()));
        assert!(verifier.bytes().all(|b| VERIFIER_ALPHABET.contains(&b)));
        assert_eq!(challenge, pkce_challenge(&verifier));
    }

    #[test]
    fn parse_auth_url_extracts_issuer_and_params() {
        let config = parse_auth_url(
            "oidc://login.microsoftonline.com/tenant-id/v2.0?client_id=abc123&scope=openid%20profile%20offline_access",
        )
        .unwrap();
        assert_eq!(
            config.issuer,
            "https://login.microsoftonline.com/tenant-id/v2.0"
        );
        assert_eq!(config.client_id, "abc123");
        assert_eq!(config.scope, "openid profile offline_access");
    }

    #[test]
    fn parse_auth_url_defaults_scope_and_requires_client_id() {
        let config =
            parse_auth_url("oidc://login.microsoftonline.com/t/v2.0?client_id=x").unwrap();
        assert_eq!(config.scope, "openid profile");

        assert!(parse_auth_url("oidc://login.microsoftonline.com/t/v2.0").is_err());
    }

    #[test]
    fn build_authorize_url_includes_pkce_and_state() {
        let url = build_authorize_url(
            "https://login.microsoftonline.com/t/oauth2/v2.0/authorize",
            "client-123",
            "http://127.0.0.1:5000/",
            "openid profile",
            "state-xyz",
            "nonce-abc",
            "challenge-987",
        )
        .unwrap();
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=challenge-987"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state-xyz"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2F"));
    }

    #[test]
    fn parse_redirect_request_extracts_code_and_state() {
        let line = "GET /?code=AUTH_CODE_123&state=state-xyz HTTP/1.1";
        let (code, state) = parse_redirect_request(line).unwrap();
        assert_eq!(code, "AUTH_CODE_123");
        assert_eq!(state, "state-xyz");

        // A request without the auth params yields nothing.
        assert!(parse_redirect_request("GET /favicon.ico HTTP/1.1").is_none());
    }
}
