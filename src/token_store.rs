//! Token storage module using system keyring for secure credential storage.
//!
//! Tokens are stored in the system keyring (Secret Service on Linux, Keychain
//! on macOS, Credential Manager on Windows) when available.
//!
//! On Linux, processes spawned by podman inherit its SELinux context
//! (container_runtime_t), which is not allowed to connect to the D-Bus
//! session socket (session_dbusd_tmp_t).  Every keyring call therefore fails
//! immediately when the credential helper is invoked by podman.
//!
//! In that case the module transparently falls back to a plain JSON file:
//!
//! - Linux/macOS: `~/.config/docker-credential-icr/tokens/<registry>.json` (mode 0600)
//! - Windows:     `%APPDATA%\docker-credential-icr\tokens\<registry>.json`
//!
//! The file is written with owner-read/write permissions only (0600 on Unix).
//! This fallback requires no configuration — it activates automatically
//! whenever a keyring operation fails.

use crate::error::{CredentialError, Result};
use chrono::{DateTime, Utc};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
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

// ---------------------------------------------------------------------------
// File-based fallback store
// ---------------------------------------------------------------------------

fn file_store_path(registry: &str) -> Option<PathBuf> {
    dirs::config_dir().map(|base| {
        let safe = registry.replace(['/', ':', '@'], "_");
        base.join("docker-credential-icr")
            .join("tokens")
            .join(format!("{}.json", safe))
    })
}

fn file_store_read(registry: &str) -> Option<StoredToken> {
    let path = file_store_path(registry)?;
    let data = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

fn file_store_write(registry: &str, token: &StoredToken) -> std::io::Result<()> {
    let path = file_store_path(registry).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Cannot determine config dir")
    })?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(token)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    fs::write(&path, json.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn file_store_delete(registry: &str) {
    if let Some(path) = file_store_path(registry) {
        let _ = fs::remove_file(path);
    }
}

// ---------------------------------------------------------------------------
// TokenStore
// ---------------------------------------------------------------------------

/// Token store for managing OAuth2 tokens.
///
/// Tries the system keyring first.  If the keyring is unavailable (e.g.
/// SELinux blocks D-Bus access when spawned by podman) the module falls back
/// automatically to a `~/.config` file store with 0600 permissions.
pub struct TokenStore {
    registry: String,
}

impl TokenStore {
    /// Create a new token store for a specific registry
    pub fn new(registry: String) -> Self {
        Self { registry }
    }

    fn access_key(&self) -> String {
        format!("{}-access", self.registry)
    }

    fn refresh_key(&self) -> String {
        format!("{}-refresh", self.registry)
    }

    fn expires_key(&self) -> String {
        format!("{}-expires", self.registry)
    }

    /// Store a token — keyring first, file store on any keyring failure.
    pub fn store_token(&self, token: &StoredToken) -> Result<()> {
        info!("Storing tokens for registry: {}", self.registry);

        // Attempt to store in the keyring.
        // Note: IBM Cloud tokens are JWT tokens with around 1600 characters.
        // The Windows Credential Manager can store up to 2560 bytes per
        // credential. Since set_password() encodes as UTF-16 that caps at
        // ~1280 characters, which isn't enough. set_secret() works around
        // this. See CRED_MAX_CREDENTIAL_BLOB_SIZE at
        // https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
        let keyring_ok = match Entry::new(SERVICE_NAME, &self.access_key()) {
            Ok(e) => match e.set_secret(token.access_token.as_bytes()) {
                Ok(()) => {
                    if let Some(ref rt) = token.refresh_token {
                        if let Ok(re) = Entry::new(SERVICE_NAME, &self.refresh_key()) {
                            if let Err(e) = re.set_secret(rt.as_bytes()) {
                                warn!("Failed to store refresh token in keyring: {}", e);
                            }
                        }
                    }
                    if let Ok(ee) = Entry::new(SERVICE_NAME, &self.expires_key()) {
                        if let Err(e) = ee.set_password(&token.expires_at.to_rfc3339()) {
                            warn!("Failed to store expiration in keyring: {}", e);
                        }
                    }
                    true
                }
                Err(e) => {
                    warn!(
                        "Keyring write failed ({}), falling back to file store",
                        e
                    );
                    false
                }
            },
            Err(e) => {
                warn!(
                    "Failed to create keyring entry ({}), falling back to file store",
                    e
                );
                false
            }
        };

        if !keyring_ok {
            debug!("Writing token to file store for: {}", self.registry);
            file_store_write(&self.registry, token).map_err(|e| {
                CredentialError::TokenStoreError(format!("File store write failed: {}", e))
            })?;
            info!("Tokens stored in file store for: {}", self.registry);
        } else {
            info!("Tokens stored in keyring for: {}", self.registry);
        }

        info!("Token expires at: {}", token.expires_at);
        Ok(())
    }

    /// Retrieve a token — keyring first, then file store.
    pub fn get_token(&self) -> Result<Option<StoredToken>> {
        debug!(
            "Attempting to retrieve token for registry: {}",
            self.registry
        );

        // Try keyring first.
        if let Ok(access_entry) = Entry::new(SERVICE_NAME, &self.access_key()) {
            match access_entry.get_secret() {
                Ok(bytes) => {
                    let access_token = match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(CredentialError::TokenStoreError(format!(
                                "Failed to decode access token: {}",
                                e
                            )))
                        }
                    };

                    let refresh_token = Entry::new(SERVICE_NAME, &self.refresh_key())
                        .ok()
                        .and_then(|e| e.get_secret().ok())
                        .and_then(|b| String::from_utf8(b).ok());

                    let expires_at = match Entry::new(SERVICE_NAME, &self.expires_key())
                        .ok()
                        .and_then(|e| e.get_password().ok())
                        .and_then(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .ok()
                                .map(|dt| dt.with_timezone(&Utc))
                        }) {
                        Some(dt) => dt,
                        None => {
                            warn!(
                                "No valid expiration in keyring for {}, treating as expired",
                                self.registry
                            );
                            return Ok(None);
                        }
                    };

                    debug!("Token retrieved from keyring for: {}", self.registry);
                    return Ok(Some(StoredToken {
                        access_token,
                        refresh_token,
                        expires_at,
                    }));
                }
                Err(keyring::Error::NoEntry) => {
                    debug!("No token in keyring for: {}", self.registry);
                    // Fall through to file store.
                }
                Err(e) => {
                    warn!(
                        "Keyring read failed ({}); falling back to file store",
                        e
                    );
                    // Fall through to file store.
                }
            }
        }

        // File store fallback.
        debug!("Checking file store for: {}", self.registry);
        Ok(file_store_read(&self.registry))
    }

    /// Delete a token from both keyring and file store.
    pub fn delete_token(&self) -> Result<()> {
        for key in &[self.access_key(), self.refresh_key(), self.expires_key()] {
            if let Ok(entry) = Entry::new(SERVICE_NAME, key) {
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => {}
                    Err(e) => warn!("Failed to delete keyring entry '{}': {}", key, e),
                }
            }
        }
        file_store_delete(&self.registry);
        debug!("Token deleted for: {}", self.registry);
        Ok(())
    }

    /// Get a valid access token, refreshing if necessary
    pub async fn get_valid_token(&self) -> Result<Option<String>> {
        match self.get_token()? {
            Some(token) => {
                if token.is_expired() {
                    info!("Access token expired for registry: {}", self.registry);
                    if let Some(refresh_token) = &token.refresh_token {
                        info!("Attempting to refresh token");
                        match self.refresh_access_token(refresh_token).await {
                            Ok(new_token) => {
                                info!("Token refreshed successfully");
                                Ok(Some(new_token))
                            }
                            Err(e) => {
                                warn!("Failed to refresh token: {}", e);
                                let _ = self.delete_token();
                                Ok(None)
                            }
                        }
                    } else {
                        info!("No refresh token available, need to re-authenticate");
                        let _ = self.delete_token();
                        Ok(None)
                    }
                } else if token.expires_soon() {
                    info!("Access token expires soon for registry: {}", self.registry);
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
                                Ok(Some(token.access_token))
                            }
                        }
                    } else {
                        Ok(Some(token.access_token))
                    }
                } else {
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

        let config = fetch_oidc_config().await?;

        let client = reqwest::Client::new();
        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", CLIENT_ID);
        params.insert("client_secret", CLIENT_SECRET);

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

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: Option<u64>,
            refresh_token: Option<String>,
        }

        let token_response: TokenResponse = response.json().await.map_err(|e| {
            CredentialError::AuthenticationError(format!("Failed to parse token response: {}", e))
        })?;

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
