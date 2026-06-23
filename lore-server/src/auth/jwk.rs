// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::jwk::EllipticCurve;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::jwk::JwkSet;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::LabelArray;
use lore_telemetry::METRICS_OPERATION_LATENCY_METRIC_NAME;
use lore_telemetry::timed;
use lore_telemetry::timer::TimedResult;
use lore_transport::grpc::user_agent;
use opentelemetry::KeyValue;
use serde::Deserialize;
use smallvec::SmallVec;
use thiserror::Error;
use tracing::warn;

#[derive(Clone)]
struct JWKServiceKey {
    #[allow(dead_code)]
    jwk: Jwk,
    decoding_key: DecodingKey,
    algorithm: jsonwebtoken::Algorithm,
}

#[derive(Clone, Default, Deserialize, Debug)]
pub struct JWKServiceSettings {
    pub endpoint: String,
}

#[derive(Error, Debug)]
pub enum JWKServiceError {
    #[error("Internal Error")]
    InternalError,
    #[error("Could not parse jwks endpoint response")]
    ParseError(#[from] serde_json::Error),
    #[error("Could not decode jwk key")]
    DecodingError(#[from] jsonwebtoken::errors::Error),
    #[error("Key for kid not found")]
    NotFound,
}

/// Infer the signing algorithm for a JWK that omits the optional `alg` member,
/// based on its key type. Returns `None` for key types/curves we cannot map to a
/// supported signing algorithm.
fn infer_algorithm(params: &AlgorithmParameters) -> Option<Algorithm> {
    match params {
        // RSA keys used for signature verification default to RS256. This covers
        // Microsoft Entra, which always signs with RS256 but does not advertise
        // `alg` in its JWKS.
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Some(Algorithm::ES256),
            EllipticCurve::P384 => Some(Algorithm::ES384),
            // jsonwebtoken has no ES512, and P-521/Ed25519 cannot be inferred to a
            // supported EC signing algorithm here.
            EllipticCurve::P521 | EllipticCurve::Ed25519 => None,
        },
        // Octet (symmetric) and OKP keys aren't supported for JWKS-based token
        // verification here.
        AlgorithmParameters::OctetKey(_) | AlgorithmParameters::OctetKeyPair(_) => None,
    }
}

/// Parse a JWKS response body and build the cache of usable keys keyed by `kid`.
fn build_key_set(body: &str) -> Result<HashMap<String, JWKServiceKey>, JWKServiceError> {
    let new_jwks: JwkSet = serde_json::from_str(body).map_err(|e| {
        warn!("Failed to parse JWKS response: {body}");
        JWKServiceError::ParseError(e)
    })?;

    let mut new_set = HashMap::new();

    for jwk in new_jwks.keys {
        let kid = jwk
            .common
            .key_id
            .as_ref()
            .ok_or(JWKServiceError::InternalError)?;

        let algorithm = match jwk.common.key_algorithm {
            Some(alg) => {
                Algorithm::from_str(&alg.to_string()).map_err(JWKServiceError::DecodingError)?
            }
            // Some IdPs (notably Microsoft Entra/Azure AD) omit the optional `alg`
            // member from their JWKS entries. Infer it from the key type rather
            // than hard-failing.
            None => infer_algorithm(&jwk.algorithm).ok_or_else(|| {
                warn!("JWK {kid} has no `alg` and its key type is unsupported for inference");
                JWKServiceError::InternalError
            })?,
        };

        new_set.insert(
            kid.clone(),
            JWKServiceKey {
                decoding_key: DecodingKey::from_jwk(&jwk).map_err(JWKServiceError::DecodingError)?,
                jwk,
                algorithm,
            },
        );
    }

    Ok(new_set)
}

#[async_trait]
pub trait JWKService: Send + Sync {
    /// Get the public key for the specified key id. Note: this may potentially result in a network
    /// call if the key for key id is not already cached locally by the implementer of this trait.
    async fn get_key(
        &self,
        kid: &str,
    ) -> Result<(DecodingKey, jsonwebtoken::Algorithm), JWKServiceError>;
}

#[derive(Clone, Default)]
pub struct JwkServiceImpl {
    // allow to be refetched from different threads if needed
    cached_set: Arc<tokio::sync::RwLock<HashMap<String, JWKServiceKey>>>,
    #[allow(dead_code)]
    settings: JWKServiceSettings,
}

impl JwkServiceImpl {
    pub fn new(settings: JWKServiceSettings) -> Self {
        JwkServiceImpl {
            cached_set: Default::default(),
            settings,
        }
    }

    async fn get_cached_key(
        &self,
        kid: &str,
    ) -> Result<(DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
        let keys = self.cached_set.read().await;
        let res = keys.get(kid).ok_or(JWKServiceError::NotFound)?;
        Ok((res.decoding_key.clone(), res.algorithm))
    }

    /// Fetch the latest keys and replace the local cache. If `desired` is not-`None`,
    /// short-circuits if the key id is already present in the local cache.
    pub async fn fetch_new_keys(&self, desired: Option<&str>) -> Result<(), JWKServiceError> {
        let mut cache = self.cached_set.write().await;

        // Check to see if the desired key was fetched while we waited for the lock.
        if desired.and_then(|d| cache.get(d)).is_some() {
            return Ok(());
        }

        let client = reqwest::Client::builder()
            .user_agent(user_agent())
            .build()
            .map_err(|e| {
                warn!("Failed to construct HTTP client: {e:?}");
                JWKServiceError::InternalError
            })?;

        let response = timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("get_keys"),
            {
                client
                    .get(&self.settings.endpoint)
                    .send()
                    .await
                    .map_err(|e| {
                        warn!("Failed to fetch JWKS endpoint: {e:?}");
                        JWKServiceError::InternalError
                    })
            }
        )
        .result?;

        let status = response.status();
        let response_body = response.text().await.map_err(|e| {
            warn!("Failed to get response body from JWKS endpoint result: {e:?}");
            JWKServiceError::InternalError
        })?;

        if !status.is_success() {
            warn!("JWKS endpoint returned error. Status: {status}, response: {response_body}");

            return Err(JWKServiceError::InternalError);
        }

        let new_set = build_key_set(response_body.as_str())?;

        *cache = new_set;

        Ok(())
    }
}

#[async_trait]
impl JWKService for JwkServiceImpl {
    async fn get_key(
        &self,
        kid: &str,
    ) -> Result<(DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
        let key = self.get_cached_key(kid).await;

        match key {
            Ok(_) => key,
            Err(JWKServiceError::NotFound) => {
                // one more try after fetch
                self.fetch_new_keys(Some(kid)).await?;
                self.get_cached_key(kid).await
            }
            Err(e) => Err(e),
        }
    }
}

impl InstrumentProvider for JwkServiceImpl {
    fn namespace(&self) -> &'static str {
        "urc.auth.jwk_service"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A representative RSA modulus (base64url, no padding). Only needs to be valid
    // base64url for `DecodingKey::from_jwk` to accept it.
    const TEST_MODULUS: &str = "k5h24fojQ1Y_d2EcJwRU2d7TvRS-4xdYBhTQsnL7A-zOtJ5gITVMaqtfpOVdIdqEei6MAhmy5uQ_aarxy25-5LZJn95FP30H1ZYH5i7LX6acso3WPCr16c-c3BDEkG53enRUdgRyX9VR8AL1I3OQKQwOshIo9QNRcnTz1XFZ-XmEPoLkZvczffuafWEKu5PFJJO9L2iHcBUkQdVE0YElvHB8U50KoCkajtxepvPtr_VI7KGubBhnSyN4xvH0u7p6_RsV0BOziQntdDOl91Fedi0tIzg4f_AGhpO9xwwFPVjJ4idSv4Tl4XmIzwXTJIArHuJB_w9EpHpO4UmxvXYpvA";

    /// Microsoft Entra/Azure AD style JWKS: RSA keys with no `alg` member and a few
    /// Entra-specific extra fields that should be ignored.
    #[test]
    fn build_key_set_infers_rs256_when_alg_absent() {
        let body = format!(
            r#"{{
                "keys": [
                    {{
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "entra-key-1",
                        "x5t": "entra-key-1",
                        "n": "{TEST_MODULUS}",
                        "e": "AQAB",
                        "x5c": ["unused"],
                        "cloud_instance_name": "microsoftonline.com",
                        "issuer": "https://login.microsoftonline.com/tenant/v2.0"
                    }}
                ]
            }}"#
        );

        let set = build_key_set(&body).expect("Entra JWKS without `alg` should parse");
        let key = set.get("entra-key-1").expect("key should be cached by kid");
        assert_eq!(key.algorithm, Algorithm::RS256);
    }

    /// A JWKS that does carry `alg` (e.g. Google) should still honor it.
    #[test]
    fn build_key_set_honors_explicit_alg() {
        let body = format!(
            r#"{{
                "keys": [
                    {{
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "google-key-1",
                        "alg": "RS256",
                        "n": "{TEST_MODULUS}",
                        "e": "AQAB"
                    }}
                ]
            }}"#
        );

        let set = build_key_set(&body).expect("JWKS with `alg` should parse");
        let key = set.get("google-key-1").expect("key should be cached by kid");
        assert_eq!(key.algorithm, Algorithm::RS256);
    }

    #[test]
    fn infer_algorithm_maps_supported_key_types() {
        use jsonwebtoken::jwk::EllipticCurveKeyParameters;
        use jsonwebtoken::jwk::EllipticCurveKeyType;
        use jsonwebtoken::jwk::RSAKeyParameters;
        use jsonwebtoken::jwk::RSAKeyType;

        let rsa = AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: TEST_MODULUS.to_string(),
            e: "AQAB".to_string(),
        });
        assert_eq!(infer_algorithm(&rsa), Some(Algorithm::RS256));

        let ec = |curve| {
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve,
                x: "x".to_string(),
                y: "y".to_string(),
            })
        };
        assert_eq!(infer_algorithm(&ec(EllipticCurve::P256)), Some(Algorithm::ES256));
        assert_eq!(infer_algorithm(&ec(EllipticCurve::P384)), Some(Algorithm::ES384));
        assert_eq!(infer_algorithm(&ec(EllipticCurve::P521)), None);
    }
}
