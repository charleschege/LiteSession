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

impl core::cmp::PartialEq for Role {
    fn eq(&self, other: &Role) -> bool {
        match (self, other) {
            (Role::SlaveNode, Role::SlaveNode)
            | (Role::MasterNode, Role::MasterNode)
            | (Role::SuperNode, Role::SuperNode)
            | (Role::SuperUser, Role::SuperUser)
            | (Role::Admin, Role::Admin)
            | (Role::User, Role::User) => true,
            (Role::Custom(value), Role::Custom(value2)) => match (value, value2) {
                (a, b) => a == b,
            },
            _ => false,
        }
    }
}

impl core::clone::Clone for Role {
    //FIXME use cfg to allow only in tests
    fn clone(&self) -> Self {
        match self {
            Self::SlaveNode => Self::SlaveNode,
            Self::MasterNode => Self::MasterNode,
            Self::SuperNode => Self::SuperNode,
            Self::SuperUser => Self::SuperUser,
            Self::Admin => Self::Admin,
            Self::User => Self::User,
            Self::Custom(inner) => Self::Custom(inner.clone()),
        }
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

impl core::cmp::PartialEq for ConfidentialityMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ConfidentialityMode::Low, ConfidentialityMode::Low)
            | (ConfidentialityMode::High, ConfidentialityMode::High) => true,
            _ => false,
        }
    }
}

impl core::clone::Clone for ConfidentialityMode {
    fn clone(&self) -> Self {
        match self {
            ConfidentialityMode::High => ConfidentialityMode::High,
            ConfidentialityMode::Low => ConfidentialityMode::Low,
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
    TokenAuthentic,
    TokenAuthorized,
    TokenRejected,
    BadToken,
    SessionExpired,
}

impl core::cmp::PartialEq for TokenOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (TokenOutcome::TokenAuthentic, TokenOutcome::TokenAuthentic)
            | (TokenOutcome::TokenAuthorized, TokenOutcome::TokenAuthorized)
            | (TokenOutcome::TokenRejected, TokenOutcome::TokenRejected)
            | (TokenOutcome::BadToken, TokenOutcome::BadToken)
            | (TokenOutcome::SessionExpired, TokenOutcome::SessionExpired) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod global_tests {
    use super::{ConfidentialityMode, Role, SessionTokenRng};

    #[test]
    fn sessiontoken_rng_tests() {
        let alphanumeric = SessionTokenRng::alphanumeric();
        let nonce = SessionTokenRng::nonce();
        assert_eq!(alphanumeric.len(), 32_usize);
        assert_eq!(nonce.len(), 12_usize);
    }

    #[test]
    fn role_tests() {
        let slavenode = Role::SlaveNode;
        let masternode = Role::MasterNode;
        let supernode = Role::SuperNode;
        let superuser = Role::SuperUser;
        let admin = Role::Admin;
        let user = Role::User;
        let custom_role = Role::Custom("Foo".into());

        assert_eq!(slavenode, Role::SlaveNode);
        assert_eq!(masternode, Role::MasterNode);
        assert_eq!(supernode, Role::SuperNode);
        assert_eq!(superuser, Role::SuperUser);
        assert_eq!(admin, Role::Admin);
        assert_eq!(user, Role::User);
        assert_eq!(custom_role, Role::Custom("Foo".into()));
        assert_ne!(custom_role, Role::Custom("Bar".into()));
        assert_ne!(user, Role::SuperUser);
    }

    #[test]
    fn confidentiality_tests() {
        let low = ConfidentialityMode::from_string("ConfidentialityMode::Low");
        let high = ConfidentialityMode::from_string("ConfidentialityMode::High");
        let invalid = ConfidentialityMode::from_string("ConfidentialityMode::Foo");

        assert_eq!(ConfidentialityMode::Low, low);
        assert_eq!(ConfidentialityMode::High, high);
        assert_eq!(ConfidentialityMode::High, invalid);
        assert_ne!(ConfidentialityMode::Low, high);
        assert_ne!(ConfidentialityMode::High, low);
    }
}
