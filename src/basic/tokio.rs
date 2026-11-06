use crate::basic::{Algorithm, HookConfig};
use argon2::{PasswordHash, PasswordVerifier};
use base64::Engine as _;
use http::{HeaderMap, StatusCode, header};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use vetis::{
    errors::RuntimeError,
    hook::{ContentHook, PostContentHook, PreProcessHook, RewriteHook},
};
use vetis_tokio::{
    Request, VetisFutureResult, VetisResult,
    errors::{HostError, VetisError},
    hook::{AccessHook, Hook, HookPhase},
    host::HostContext,
};

/// BasicAuth holds actual data for basic auth purposes
///
/// # Notes
///
/// If htpasswd file is provided, that will populate
/// users map only if users map wasn't previously set.
pub struct BasicAuthHook {
    users: Arc<RwLock<HashMap<String, String>>>,
    algo: Algorithm,
    htpasswd: Option<PathBuf>,
    realm: Option<String>,
}

impl BasicAuthHook {
    /// Build a new BasicAuth out of its configuration
    pub fn new(config: HookConfig) -> Self {
        let users = Arc::new(RwLock::new(config.users));
        let algo = config
            .algorithm
            .clone();
        Self {
            users,
            algo,
            htpasswd: config
                .htpasswd
                .clone(),
            realm: config.realm.clone(),
        }
    }
}

impl Hook for BasicAuthHook {
    fn has_matches(&self, _path: &Request) -> bool {
        true
    }

    fn phase(&self) -> &HookPhase {
        &HookPhase::Access
    }

    fn as_preprocess_hook(&self) -> Option<&dyn PreProcessHook> {
        None
    }

    fn as_rewrite_hook(&self) -> Option<&dyn RewriteHook> {
        None
    }

    fn as_access_hook(&self) -> Option<&dyn AccessHook> {
        Some(self)
    }

    fn as_content_hook(&self) -> Option<&dyn ContentHook> {
        None
    }

    fn as_postcontent_hook(&self) -> Option<&dyn PostContentHook> {
        None
    }
}

impl AccessHook for BasicAuthHook {
    fn validate(
        &self,
        request: Request,
        host_context: HostContext,
    ) -> VetisFutureResult<'static, (Request, HostContext)> {
        let users = self.users.clone();
        let algo = self.algo.clone();
        let file = self
            .htpasswd
            .clone();

        let headers = if let Some(realm) = &self.realm {
            let mut header_map = HeaderMap::new();
            header_map.insert(
                header::WWW_AUTHENTICATE,
                format!("Basic realm={}", realm)
                    .parse()
                    .unwrap(),
            );
            header_map
        } else {
            HeaderMap::new()
        };

        let headers = headers.clone();
        let future = async move {
            let users = if users
                .read()
                .await
                .is_empty()
                && let Some(file) = &file
                && file.exists()
            {
                let users_from_file = load_users_from_file(file, &headers).await?;
                users
                    .write()
                    .await
                    .clone_from(&users_from_file);
                users
            } else {
                users
            };

            let common_error = VetisError::Host(HostError::Runtime(
                RuntimeError::new("Could not authenticate")
                    .with_status_code(StatusCode::UNAUTHORIZED)
                    .with_headers(headers.clone()),
            ));

            let Some(auth_header) = request
                .headers()
                .get(http::header::AUTHORIZATION)
            else {
                return Err(common_error);
            };

            let Ok(auth_header) = auth_header.to_str() else {
                return Err(common_error);
            };

            let Some(pair) = auth_header.strip_prefix("Basic ") else {
                return Err(common_error);
            };

            let auth_header = base64::engine::general_purpose::STANDARD.decode(pair);
            let auth_header = auth_header.map_err(|e| {
                VetisError::Host(HostError::Runtime(
                    RuntimeError::new(&format!("Could not decode header: {}", e))
                        .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        .with_headers(headers.clone()),
                ))
            })?;

            let auth_header = String::from_utf8(auth_header).map_err(|_| {
                VetisError::Host(HostError::Runtime(
                    RuntimeError::new("Invalid Authorization header")
                        .with_status_code(StatusCode::UNAUTHORIZED)
                        .with_headers(headers.clone()),
                ))
            })?;

            let (username, password) = auth_header
                .split_once(':')
                .ok_or(VetisError::Host(HostError::Runtime(
                    RuntimeError::new("Invalid credentials")
                        .with_status_code(StatusCode::UNAUTHORIZED)
                        .with_headers(headers.clone()),
                )))?;

            let guard = users.read().await;
            let saved_password = guard
                .get(username)
                .cloned();
            drop(guard);

            if let Some(hashed_password) = saved_password {
                let password = password.to_string();
                let verify_task = tokio::task::spawn_blocking(move || {
                    verify_password(password, hashed_password, algo)
                })
                .await;

                let auth_success = match verify_task {
                    Ok(result) => result,
                    Err(e) => {
                        return Err(VetisError::Host(HostError::Runtime(
                            RuntimeError::new(&format!("Could not verify password: {}", e))
                                .with_status_code(StatusCode::UNAUTHORIZED)
                                .with_headers(headers),
                        )));
                    }
                };

                if auth_success {
                    return Ok((request, host_context));
                } else {
                    return Err(common_error);
                }
            }

            Err(common_error)
        };

        Box::pin(future)
    }
}

async fn load_users_from_file(
    file: &PathBuf,
    headers: &HeaderMap,
) -> VetisResult<HashMap<String, String>> {
    let htpasswd = if file.exists() {
        file
    } else {
        return Err(VetisError::Host(HostError::Runtime(
            RuntimeError::new(".htpasswd file does not exists")
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .with_headers(headers.clone()),
        )));
    };

    let htpasswd = tokio::fs::read_to_string(htpasswd).await;
    let mut users = HashMap::new();
    match htpasswd {
        Ok(file) => {
            file.lines()
                .for_each(|line| {
                    let credentials = line.split_once(':');

                    if let Some(credentials) = credentials {
                        users.insert(
                            credentials
                                .0
                                .to_string(),
                            credentials
                                .1
                                .to_string(),
                        );
                    }
                });
        }
        Err(e) => {
            log::error!("Failed to read htpasswd file: {}", e);
        }
    }
    Ok(users)
}

fn verify_password(password: String, hashed_password: String, algorithm: Algorithm) -> bool {
    match algorithm {
        Algorithm::BCrypt => {
            bcrypt::verify(password.as_str(), hashed_password.as_str()).unwrap_or(false)
        }
        Algorithm::Argon2 => {
            let argon2 = argon2::Argon2::default();
            let parsed_hash = PasswordHash::new(hashed_password.as_str());
            match parsed_hash {
                Ok(parsed_hash) => {
                    let result = argon2.verify_password(password.as_bytes(), &parsed_hash);
                    result.is_ok()
                }
                Err(_) => false,
            }
        }
    }
}
