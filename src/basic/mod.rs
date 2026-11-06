#[cfg(feature = "runtime-tokio")]
use crate::basic::tokio::BasicAuthHook;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use vetis::{
    VetisHook, VetisResult,
    errors::{ConfigError, VetisError},
    matcher::MatcherConfig,
};

#[cfg(feature = "runtime-tokio")]
/// Tokio runtime support
pub mod tokio;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
/// An enum with authentication algorithms.
///
/// # Variants
///
/// * `BCrypt` - The bcrypt algorithm.
/// * `Argon2` - The argon2 algorithm.
pub enum Algorithm {
    /// The bcrypt algorithm.
    BCrypt,
    /// The argon2 algorithm.
    Argon2,
}

/// A builder for creating a `BasicAuthConfig`.
pub struct HookConfigBuilder {
    users: HashMap<String, String>,
    realm: Option<String>,
    algorithm: Algorithm,
    htpasswd: Option<PathBuf>,
}

impl HookConfigBuilder {
    /// Allow set a hashmap of user and passowrd
    ///
    /// # Returns
    ///
    /// * `Self` - The builder.
    pub fn users(mut self, users: HashMap<String, String>) -> Self {
        self.users = users;
        self
    }

    /// Allow set realm
    ///
    /// # Returns
    ///
    /// * `Self` - The builder.
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Allow set the algorithm
    ///
    /// # Returns
    ///
    /// * `Self` - The builder.
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Allow set the htpasswd file
    ///
    /// # Returns
    ///
    /// * `Self` - The builder.
    pub fn htpasswd(mut self, htpasswd: PathBuf) -> Self {
        self.htpasswd = Some(htpasswd);
        self
    }

    /// Build the `HookConfig` with the configured settings.
    ///
    /// # Returns
    ///
    /// * `VetisResult<HookConfig>` - The `HookConfig` with the configured settings.
    pub fn build(self) -> VetisResult<HookConfig> {
        if let Some(htpasswd) = &self.htpasswd {
            let htpasswd = Path::new(htpasswd);
            if !htpasswd.exists() {
                return Err(VetisError::Config(ConfigError::Auth(
                    ".htpasswd file not found".to_string(),
                )));
            }
        }

        Ok(HookConfig {
            matchers: None,
            users: self.users,
            realm: self.realm,
            algorithm: self.algorithm,
            htpasswd: self.htpasswd,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A struct with basic authentication configuration.
///
/// # Fields
///
/// * `users` - A map of username to hashed password.
/// * `algorithm` - The algorithm used for password hashing.
/// * `htpasswd` - The path to the htpasswd file.
///
/// # Examples
///
/// ```rust,no_run
/// use std::collections::HashMap;
/// use vetis::auth::{Algorithm, BasicAuthConfig};
///
/// let auth = BasicAuthConfig::builder()
///     .users(HashMap::new())
///     .algorithm(Algorithm::BCrypt)
///     .build();
/// ```
pub struct HookConfig {
    matchers: Option<Vec<Box<dyn MatcherConfig>>>,
    users: HashMap<String, String>,
    realm: Option<String>,
    algorithm: Algorithm,
    htpasswd: Option<PathBuf>,
}

#[typetag::serde(name = "basic_auth")]
impl vetis::hook::HookConfig for HookConfig {
    fn matchers(&self) -> Option<&Vec<Box<dyn MatcherConfig>>> {
        self.matchers
            .as_ref()
    }

    fn boxed_clone(&self) -> Box<dyn vetis::hook::HookConfig> {
        Box::new(self.clone())
    }

    fn boxed_hook(&self) -> Box<dyn VetisHook> {
        Box::new(BasicAuthHook::new(self.clone()))
    }
}

impl HookConfig {
    /// Creates a new `HookConfigBuilder` with default settings.
    ///
    /// # Returns
    ///
    /// * `HookConfigBuilder` - The builder.
    pub fn builder() -> HookConfigBuilder {
        HookConfigBuilder {
            users: HashMap::new(),
            realm: None,
            algorithm: Algorithm::BCrypt,
            htpasswd: None,
        }
    }

    /// Returns users
    ///
    /// # Returns
    ///
    /// * `&HashMap<String, String>` - The users.
    pub fn users(&self) -> &HashMap<String, String> {
        &self.users
    }

    /// Returns the algorithm used for password hashing.
    ///
    /// # Returns
    ///
    /// * `&Algorithm` - The algorithm used for password hashing.
    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    /// Returns the path to the htpasswd file.
    ///
    /// # Returns
    ///
    /// * `&Option<PathBuf>` - The path to the htpasswd file.
    pub fn htpasswd(&self) -> &Option<PathBuf> {
        &self.htpasswd
    }
}
