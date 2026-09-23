//! Token storage module using system keyring for secure credential storage
//!
//! This module provides secure storage for OAuth2 tokens (access and refresh tokens)
//! using the system's native credential store (Keychain on macOS, Credential Manager
//! on Windows, Secret Service on Linux).
//!
//! When the keyring is unavailable (e.g. no D-Bus session inside a container or
//! devcontainer bootstrap subprocess), token retrieval returns `None` so that the
//! caller falls back to a fresh OAuth2 flow.  Token storage failures are logged as
//! warnings but do not abort the operation — the freshly-obtained token is still
//! returned to the caller for this invocation.

use crate::error::{CredentialError, Result};
use chrono::{DateTime, Utc};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

const SERVICE_NAME: &str = "docker-credential-icr";

/// Stored token data including access token, refresh token, and expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    /// OAuth2 access token
    pub access_token: String,
    /// OAuth2 refresh token (optional)
    pub refresh_token: Option<String>,
    /// Token expiration time (UTC)
    pub expires_at: DateTime<Utc>,
}

impl StoredToken {
    /// Create a new stored token
    pub fn new(access_token: String, refresh_token: Option<String>, expires_in: u64) -> Self {
        let expires_at = Utc::now() + chrono::Duration::seconds(expires_in as i64);
        Self {
            access_token,
            refresh_token,
            expires_at,
        }
    }

    /// Check if the access token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if the access token will expire soon (within 5 minutes)
    pub fn expires_soon(&self) -> bool {
        let threshold = Utc::now() + chrono::Duration::minutes(5);
        self.expires_at <= threshold
    }
}

/// Token store for managing OAuth2 tokens in system keyring
pub struct TokenStore {
    registry: String,
}

impl TokenStore {
    /// Create a new token store for a specific registry
    pub fn new(registry: String) -> Self {
        Self { registry }
    }

    /// Get the keyring entry for access token
    fn get_access_token_entry(&self) -> Result<Entry> {
        let key = format!("{}-access", self.registry);
        Entry::new(SERVICE_NAME, &key).map_err(|e| {
            CredentialError::TokenStoreError(format!("Failed to access keyring: {}", e))
        })
    }

    /// Get the keyring entry for refresh token
    fn get_refresh_token_entry(&self) -> Result<Entry> {
        let key = format!("{}-refresh", self.registry);
        Entry::new(SERVICE_NAME, &key).map_err(|e| {
            CredentialError::TokenStoreError(format!("Failed to access keyring: {}", e))
        })
    }

    /// Get the keyring entry for expiration time
    fn get_expiration_entry(&self) -> Result<Entry> {
        let key = format!("{}-expires", self.registry);
        Entry::new(SERVICE_NAME, &key).map_err(|e| {
            CredentialError::TokenStoreError(format!("Failed to access keyring: {}", e))
        })
    }

    /// Store a token in the system keyring.
    ///
    /// If the keyring is unavailable (e.g. no D-Bus session) the failure is
    /// logged as a warning and the function returns `Ok(())` so that the
    /// freshly-obtained token can still be returned to the Docker/Podman caller
    /// for this invocation.  The next invocation will simply perform OAuth again.
    pub fn store_token(&self, token: &StoredToken) -> Result<()> {
        info!("Storing tokens for registry: {}", self.registry);

        // Note: IBM Cloud tokens are JWT tokens with around 1600 characters. The Windows Credential
        // Manager can store up to 2560 bytes of data per credential. Since set_password() encodes
        // the password as UTF-16 string that means we end up with a maximum of 1280 characters,
        // which isn't sufficient. Storing the token as bytes using set_secret() works around that
        // limitation.
        //
        // See also CRED_MAX_CREDENTIAL_BLOB_SIZE at
        // https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw.

        // Store access token
        let access_entry = self.get_access_token_entry()?;
        if let Err(e) = access_entry.set_secret(token.access_token.as_bytes()) {
            warn!(
                "Failed to store access token in keyring (keyring unavailable?): {}",
                e
            );
            // Cannot persist the token this invocation, but don't fail — the
            // caller still has a valid token to return.
            return Ok(());
        }

        // Store refresh token
        if let Some(ref refresh_token) = token.refresh_token {
            let refresh_entry = self.get_refresh_token_entry()?;
            if let Err(e) = refresh_entry.set_secret(refresh_token.as_bytes()) {
                warn!("Failed to store refresh token in keyring: {}", e);
            }
        }

        // Store expiration time
        let expires_rfc3339 = token.expires_at.to_rfc3339();
        let expires_entry = self.get_expiration_entry()?;
        if let Err(e) = expires_entry.set_password(&expires_rfc3339) {
            warn!("Failed to store token expiration in keyring: {}", e);
        }

        info!("Tokens stored successfully for registry: {}", self.registry);
        info!("Token expires at: {}", token.expires_at);
        Ok(())
    }

    /// Retrieve a token from the system keyring.
    ///
    /// Returns `Ok(None)` — rather than an error — when the keyring is
    /// unavailable due to a platform error (e.g. D-Bus not reachable inside a
    /// container).  This allows the caller to fall back to a fresh OAuth2 flow
    /// instead of terminating with an error.
    pub fn get_token(&self) -> Result<Option<StoredToken>> {
        debug!(
            "Attempting to retrieve token for registry: {}",
            self.registry
        );

        // Try to get access token
        let access_entry = self.get_access_token_entry()?;
        let access_token = match access_entry.get_secret() {
            Ok(bytes) => {
                debug!("Successfully retrieved access token from keyring");
                String::from_utf8(bytes).map_err(|e| {
                    CredentialError::TokenStoreError(format!(
                        "Failed to decode access token: {}",
                        e
                    ))
                })?
            }
            Err(keyring::Error::NoEntry) => {
                debug!(
                    "No access token found in keyring for registry: {}",
                    self.registry
                );
                return Ok(None);
            }
            Err(e) => {
                // Platform error (e.g. D-Bus unavailable): treat as cache miss
                // so the caller proceeds with a fresh OAuth2 flow.
                warn!(
                    "Keyring read failed ({}); treating as cache miss, will re-authenticate",
                    e
                );
                return Ok(None);
            }
        };

        // Try to get refresh token (optional)
        let refresh_entry = self.get_refresh_token_entry()?;
        let refresh_token = match refresh_entry.get_secret() {
            Ok(bytes) => {
                debug!("Successfully retrieved refresh token from keyring");
                Some(String::from_utf8(bytes).map_err(|e| {
                    CredentialError::TokenStoreError(format!(
                        "Failed to decode refresh token: {}",
                        e
                    ))
                })?)
            }
            Err(keyring::Error::NoEntry) => {
                debug!("No refresh token found in keyring");
                None
            }
            Err(e) => {
                warn!("Failed to retrieve refresh token from keyring: {}", e);
                None
            }
        };

        // Try to get expiration time
        let expires_entry = self.get_expiration_entry()?;
        let expires_at = match expires_entry.get_password() {
            Ok(expires_str) => {
                debug!(
                    "Successfully retrieved expiration from keyring: {}",
                    expires_str
                );
                DateTime::parse_from_rfc3339(&expires_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| {
                        CredentialError::TokenStoreError(format!(
                            "Failed to parse expiration: {}",
                            e
                        ))
                    })?
            }
            Err(keyring::Error::NoEntry) => {
                // If no expiration stored, assume token is expired
                warn!("No expiration time found in keyring for stored token, assuming expired");
                return Ok(None);
            }
            Err(e) => {
                warn!("Failed to retrieve expiration from keyring: {}", e);
                return Ok(None);
            }
        };

        info!(
            "Successfully retrieved complete token from keyring for registry: {}",
            self.registry
        );
        debug!("Token expires at: {}", expires_at);

        Ok(Some(StoredToken {
            access_token,
            refresh_token,
            expires_at,
        }))
    }

    /// Delete a token from the system keyring
    pub fn delete_token(&self) -> Result<()> {
        let mut deleted = false;

        // Delete access token
        if let Ok(entry) = self.get_access_token_entry() {
            match entry.delete_credential() {
                Ok(()) => deleted = true,
                Err(keyring::Error::NoEntry) => {}
                Err(e) => warn!("Failed to delete access token: {}", e),
            }
        }

        // Delete refresh token
        if let Ok(entry) = self.get_refresh_token_entry() {
            match entry.delete_credential() {
                Ok(()) => deleted = true,
                Err(keyring::Error::NoEntry) => {}
                Err(e) => warn!("Failed to delete refresh token: {}", e),
            }
        }

        // Delete expiration
        if let Ok(entry) = self.get_expiration_entry() {
            match entry.delete_credential() {
                Ok(()) => deleted = true,
                Err(keyring::Error::NoEntry) => {}
                Err(e) => warn!("Failed to delete expiration: {}", e),
            }
        }

        if deleted {
            info!("Token deleted successfully for registry: {}", self.registry);
        } else {
            debug!("No token to delete for registry: {}", self.registry);
        }

        Ok(())
    }

    /// Get a valid access token, refreshing if necessary
    pub async fn get_valid_token(&self) -> Result<Option<String>> {
        match self.get_token()? {
            Some(token) => {
                if token.is_expired() {
                    info!("Access token expired for registry: {}", self.registry);
                    // Token is expired, try to refresh if we have a refresh token
                    if let Some(refresh_token) = &token.refresh_token {
                        info!("Attempting to refresh token");
                        match self.refresh_access_token(refresh_token).await {
                            Ok(new_token) => {
                                info!("Token refreshed successfully");
                                Ok(Some(new_token))
                            }
                            Err(e) => {
                                warn!("Failed to refresh token: {}", e);
                                // Delete the expired token
                                let _ = self.delete_token();
                                Ok(None)
                            }
                        }
                    } else {
                        info!("No refresh token available, need to re-authenticate");
                        // No refresh token, delete expired token
                        let _ = self.delete_token();
                        Ok(None)
                    }
                } else if token.expires_soon() {
                    info!("Access token expires soon for registry: {}", self.registry);
                    // Token expires soon, try to refresh proactively
                    if let Some(refresh_token) = &token.refresh_token {
                        match self.refresh_access_token(refresh_token).await {
                            Ok(new_token) => {
                                info!("Token refreshed proactively");
                                Ok(Some(new_token))
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to refresh token proactively, using existing token: {}",
                                    e
                                );
                                // Use existing token if refresh fails
                                Ok(Some(token.access_token))
                            }
                        }
                    } else {
                        // No refresh token, use existing token
                        Ok(Some(token.access_token))
                    }
                } else {
                    // Token is still valid
                    debug!("Using cached valid token");
                    Ok(Some(token.access_token))
                }
            }
            None => {
                debug!("No token found in store");
                Ok(None)
            }
        }
    }

    /// Refresh an access token using a refresh token
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<String> {
        use crate::oauth::{CLIENT_ID, CLIENT_SECRET};
        use crate::oidc::fetch_oidc_config;
        use std::collections::HashMap;

        debug!("Refreshing access token");

        // Fetch OIDC configuration to get token endpoint
        let config = fetch_oidc_config().await?;

        // Build refresh token request
        let client = reqwest::Client::new();
        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", CLIENT_ID);
        params.insert("client_secret", CLIENT_SECRET);

        // Send refresh token request
        let response = client
            .post(&config.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                CredentialError::NetworkError(format!("Failed to refresh token: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(CredentialError::AuthenticationError(format!(
                "Token refresh failed with status {}: {}",
                status, body
            )));
        }

        // Parse response
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: Option<u64>,
            refresh_token: Option<String>,
        }

        let token_response: TokenResponse = response.json().await.map_err(|e| {
            CredentialError::AuthenticationError(format!("Failed to parse token response: {}", e))
        })?;

        // Store the new token
        let new_token = StoredToken::new(
            token_response.access_token.clone(),
            token_response
                .refresh_token
                .or_else(|| Some(refresh_token.to_string())),
            token_response.expires_in.unwrap_or(3600),
        );

        self.store_token(&new_token)?;

        Ok(token_response.access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_expiration() {
        let token = StoredToken::new("test_token".to_string(), None, 3600);
        assert!(!token.is_expired());
        assert!(!token.expires_soon());

        let expired_token = StoredToken::new("test_token".to_string(), None, 0);
        assert!(expired_token.is_expired());
    }
}
