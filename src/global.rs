use core::fmt::{self, Debug, Display};
use nanorand::{ChaCha, RNG};

#[derive(Debug)]
pub struct SessionTokenRng;

impl SessionTokenRng {
    pub fn alphanumeric() -> String {
        let mut rng = ChaCha::new(8);
        let mut alphabet = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
            "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9",
        ];
        rng.shuffle(&mut alphabet);
        let mut random = String::default();
        alphabet
            .iter()
            .take(32)
            .for_each(|character| random.push_str(character));

        random
    }

    pub fn nonce() -> String {
        let mut rng = ChaCha::new(8);
        let mut alphabet = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
            "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9",
        ];
        rng.shuffle(&mut alphabet);
        let mut random = String::default();
        alphabet
            .iter()
            .take(12)
            .for_each(|character| random.push_str(character));

        random
    }
}

#[derive(Debug)]
pub enum Role {
    SlaveNode,
    MasterNode,
    SuperNode,
    SuperUser,
    Admin,
    User,
    Custom(String), //FIXME make this generic
}

impl Default for Role {
    fn default() -> Self {
        Self::User
    }
}

impl Role {
    pub fn from_str(role: &str) -> Self {
        match role {
            "SlaveNode" => Role::SlaveNode,
            "MasterNode" => Role::MasterNode,
            "SuperNode" => Role::SuperNode,
            "SuperUser" => Role::SuperUser,
            "Admin" => Role::Admin,
            "User" => Role::User,
            _ => Role::Custom(role.into()),
        }
    }

    pub fn to_string(role: &Role) -> String {
        match role {
            Role::SlaveNode => "SlaveNode".into(),
            Role::MasterNode => "MasterNode".into(),
            Role::SuperNode => "SuperNode".into(),
            Role::SuperUser => "SuperUser".into(),
            Role::Admin => "Admin".into(),
            Role::User => "User".into(),
            Role::Custom(role) => role.into(),
        }
    }
}

pub enum ConfidentialityMode {
    /// Data field is unencrypted
    Low,
    /// Data field is encrypted
    High,
}

impl Default for ConfidentialityMode {
    fn default() -> Self {
        ConfidentialityMode::High
    }
}

impl Debug for ConfidentialityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "{:?}", self),
            Self::High => write!(f, "{}", "ConfidentialityMode::Low"),
        }
    }
}

impl Display for ConfidentialityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "{:?}", self),
            Self::High => write!(f, "{}", "ConfidentialityMode::High"),
        }
    }
}

impl ConfidentialityMode {
    pub fn to_string(value: &ConfidentialityMode) -> &'static str {
        match value {
            ConfidentialityMode::High => "ConfidentialityMode::High",
            ConfidentialityMode::Low => "ConfidentialityMode::Low",
        }
    }

    pub fn from_string(value: &str) -> Self {
        match value {
            "ConfidentialityMode::Low" => ConfidentialityMode::Low,
            _ => ConfidentialityMode::High,
        }
    }
}

#[derive(Debug)]
pub enum TokenOutcome {
    Authorized,
    Rejected,
    BadToken,
    Authentic,
}
