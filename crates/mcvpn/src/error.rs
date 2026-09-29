use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error("network io: {0}")]
    Io(#[from] std::io::Error),
    #[error("minecraft protocol: {0}")]
    Mc(#[from] mc_protocol::McError),
    #[error("kicked from server: {0}")]
    Kick(String),
    /// The server closed the tunnel cleanly (restart/update/deploy). A kick
    /// for a policy reason (bad token, full server) needs the user; a clean
    /// close is exactly the case auto-reconnect exists for.
    #[error("closed by server")]
    Closed,
    #[error("timed out")]
    Timeout,
    #[error("authentication failed")]
    Auth,
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("device: {0}")]
    Device(String),
    #[error("shutdown")]
    Shutdown,
}

impl VpnError {
    /// Kick reasons arrive as JSON chat components; flatten for display.
    pub fn kick_reason(&self) -> Option<&str> {
        match self {
            VpnError::Kick(r) => Some(r.as_str()),
            _ => None,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            // Middleboxes and resets can corrupt a stream mid-flight (Mc /
            // Crypto errors): a fresh attempt is the right response. Kicks
            // (bad token, server full) and device errors need the user.
            VpnError::Io(_)
                | VpnError::Timeout
                | VpnError::Shutdown
                | VpnError::Closed
                | VpnError::Mc(_)
                | VpnError::Crypto(_)
        )
    }
}

pub type VpnResult<T> = Result<T, VpnError>;
