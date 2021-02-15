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
