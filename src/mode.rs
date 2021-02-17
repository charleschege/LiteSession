///This describes which mode to use for the authentication/authorization.
/// Use `LiteSessionMode::Passive` to bypass session ID pinning of the user session
/// to the token. This is vulnerable to `Denning-Sacco Attack`
///
/// Use `LiteSessionMode::SessionID(id)` to pin the current user session ID
/// to the token. This prevents `Denning-Sacco Attack`. An example of a sessionID
///is the Transport Layer Security(TLS) `session key`
#[derive(Debug)]
pub enum LiteSessionMode {
    /// SessionID of the transport protocol to be used as part of the mac
    SessionID(String),
    /// Ignores the transport protocol SessionID eg. TLS SessionID
    Passive,
}

impl Default for LiteSessionMode {
    fn default() -> Self {
        Self::Passive
    }
}

impl core::cmp::PartialEq for LiteSessionMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LiteSessionMode::Passive, LiteSessionMode::Passive) => true,
            (LiteSessionMode::SessionID(id1), LiteSessionMode::SessionID(id2)) => {
                if id1 == id2 {
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

impl core::clone::Clone for LiteSessionMode {
    fn clone(&self) -> Self {
        match self {
            LiteSessionMode::Passive => LiteSessionMode::Passive,
            LiteSessionMode::SessionID(id) => LiteSessionMode::SessionID(id.clone()),
        }
    }
}
