use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Session token for WebSocket authentication
#[derive(Debug, Clone)]
pub struct SessionToken(String);

impl SessionToken {
    /// Generate a new random session token
    pub fn generate() -> Self {
        use rand::Rng;
        let token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        Self(token)
    }

    /// Get the token as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate a token string against this token
    pub fn validate(&self, candidate: &str) -> bool {
        // Constant-time comparison to prevent timing attacks
        if self.0.len() != candidate.len() {
            return false;
        }
        let mut result = 0u8;
        for (a, b) in self.0.bytes().zip(candidate.bytes()) {
            result |= a ^ b;
        }
        result == 0
    }
}

/// PTY I/O channels for interactive sessions
pub struct PtyChannels {
    /// Send bytes to PTY stdin
    pub stdin_tx: mpsc::Sender<Vec<u8>>,
    /// Receive bytes from PTY stdout
    pub stdout_rx: mpsc::Receiver<Vec<u8>>,
}

impl std::fmt::Debug for PtyChannels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyChannels")
            .field("stdin_tx", &"mpsc::Sender<Vec<u8>>")
            .field("stdout_rx", &"mpsc::Receiver<Vec<u8>>")
            .finish()
    }
}

/// PTY session information
pub struct PtySession {
    /// Authentication token for WebSocket access
    pub token: SessionToken,
    /// PTY I/O channels (None until executor provides them)
    pub channels: Option<PtyChannels>,
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession")
            .field("token", &self.token)
            .field("channels", &self.channels.as_ref().map(|_| "Some(...)"))
            .finish()
    }
}

/// Global session registry for active WebSocket sessions
#[derive(Clone, Debug)]
pub struct SessionRegistry {
    sessions: Arc<RwLock<HashMap<String, PtySession>>>,
}

impl SessionRegistry {
    /// Create a new empty session registry
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new interactive session (creates token, channels added later)
    pub async fn register(&self, job_id: String) -> SessionToken {
        let token = SessionToken::generate();
        let session = PtySession {
            token: token.clone(),
            channels: None,
        };

        let mut sessions = self.sessions.write().await;
        let _ = sessions.insert(job_id.clone(), session);

        tracing::info!(job_id = %job_id, "registered interactive session");
        token
    }

    /// Store PTY channels for a session (called by executor after PTY is created)
    pub async fn set_channels(
        &self,
        job_id: &str,
        stdin_tx: mpsc::Sender<Vec<u8>>,
        stdout_rx: mpsc::Receiver<Vec<u8>>,
    ) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(job_id) {
            session.channels = Some(PtyChannels {
                stdin_tx,
                stdout_rx,
            });
            tracing::info!(job_id = %job_id, "attached PTY channels to session");
            true
        } else {
            false
        }
    }

    /// Take PTY channels from session (moves ownership to caller, e.g., WebSocket handler)
    pub async fn take_channels(&self, job_id: &str) -> Option<PtyChannels> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(job_id) {
            session.channels.take()
        } else {
            None
        }
    }

    /// Validate a session token
    pub async fn validate_token(&self, job_id: &str, token: &str) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(job_id) {
            session.token.validate(token)
        } else {
            false
        }
    }

    /// Remove a session when the job completes
    pub async fn remove(&self, job_id: &str) {
        let mut sessions = self.sessions.write().await;
        let _ = sessions.remove(job_id);
        tracing::info!(job_id = %job_id, "removed interactive session");
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}
