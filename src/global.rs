use core::fmt::{self, Debug, Display};
use nanorand::{ChaCha, RNG};

/// A CSPRNG random string generator using the `nanorand` crate using its `ChaCha` mode
#[derive(Debug)]
pub struct SessionTokenRng;

impl SessionTokenRng {
    /// Generate a CSPRNG string. This is used to generate the random user identifiers for the token
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

    /// Generate a secure nonce string using `nanorand` crate and its `ChaCha` random number generator
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

/// The client/server roles
#[derive(Debug)]
pub enum Role {
    /// A slave node connected to a master node
    SlaveNode,
    /// A master node that handles slave nodes
    /// It may or may not be connected to an authoritative super node
    MasterNode,
    /// An authoritative node that can handle master nodes and their slaves
    SuperNode,
    /// A node that handles verifying security, heartbeats, elections and lifetime of the nodes
    VerifierNode,
    /// A node that acts as a service registry
    RegistryNode,
    /// A node that only handles storage of data
    StorageNode,
    /// A node that acts a firewall for blacklists/whitelists, DNS requests and networks access
    FirewallNode,
    /// A node that routes inbound and outbound requests
    RouterNode,
    /// A client with highest level or root level permissions
    SuperUser,
    /// A client with administrative capabilities
    Admin,
    /// A normal client
    User,
    /// A client with a custom role
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
            | (Role::VerifierNode, Role::VerifierNode)
            | (Role::RegistryNode, Role::RegistryNode)
            | (Role::StorageNode, Role::StorageNode)
            | (Role::FirewallNode, Role::FirewallNode)
            | (Role::RouterNode, Role::RouterNode)
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
            Self::VerifierNode => Self::VerifierNode,
            Self::RegistryNode => Self::RegistryNode,
            Self::StorageNode => Self::StorageNode,
            Self::FirewallNode => Self::FirewallNode,
            Self::RouterNode => Self::RouterNode,
            Self::SuperUser => Self::SuperUser,
            Self::Admin => Self::Admin,
            Self::User => Self::User,
            Self::Custom(inner) => Self::Custom(inner.clone()),
        }
    }
}

impl Role {
    /// Converts a string `Role` to its enum variant
    pub fn from_str(role: &str) -> Self {
        match role {
            "SlaveNode" => Role::SlaveNode,
            "MasterNode" => Role::MasterNode,
            "SuperNode" => Role::SuperNode,
            "VerifierNode" => Role::VerifierNode,
            "RegistryNode" => Role::RegistryNode,
            "StorageNode" => Role::StorageNode,
            "FirewallNode" => Role::FirewallNode,
            "RouterNode" => Role::RouterNode,
            "SuperUser" => Role::SuperUser,
            "Admin" => Role::Admin,
            "User" => Role::User,
            _ => Role::Custom(role.into()),
        }
    }
    /// COnverts a `Role` into a string text
    pub fn to_string(role: &Role) -> String {
        match role {
            Role::SlaveNode => "SlaveNode".into(),
            Role::MasterNode => "MasterNode".into(),
            Role::SuperNode => "SuperNode".into(),
            Role::VerifierNode => "VerifierNode".into(),
            Role::RegistryNode => "RegistryNode".into(),
            Role::StorageNode => "StorageNode".into(),
            Role::FirewallNode => "FirewallNode".into(),
            Role::RouterNode => "RouterNode".into(),
            Role::SuperUser => "SuperUser".into(),
            Role::Admin => "Admin".into(),
            Role::User => "User".into(),
            Role::Custom(role) => role.into(),
        }
    }
}

/// The securoty mode of the data field in the token
pub enum ConfidentialityMode {
    /// Data field is unencrypted
    Low, //TODO add method to build this
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
    /// Convert `ConfidentialityMode` into a static string
    pub fn to_string(value: &ConfidentialityMode) -> &'static str {
        match value {
            ConfidentialityMode::High => "ConfidentialityMode::High",
            ConfidentialityMode::Low => "ConfidentialityMode::Low",
        }
    }
    /// Convert `ConfidentialityMode` string into its enum variant
    pub fn from_string(value: &str) -> Self {
        match value {
            "ConfidentialityMode::Low" => ConfidentialityMode::Low,
            _ => ConfidentialityMode::High,
        }
    }
}

/// Shows the outcome of verifying the validity of a token
#[derive(Debug)]
pub enum TokenOutcome {
    /// The token has been proved to be authentic
    TokenAuthentic,
    /// The token has been authorized for provided capabilities
    TokenAuthorized, //TODO create methods to handle this
    /// The token is not authentic and has been rejected
    TokenRejected,
    /// The token has been revoked by the server
    TokenRevoked,
    /// The token is invalid in its structure or length
    BadToken,
    /// The session held by the provided token has expired
    SessionExpired,
}

impl core::cmp::PartialEq for TokenOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (TokenOutcome::TokenAuthentic, TokenOutcome::TokenAuthentic)
            | (TokenOutcome::TokenAuthorized, TokenOutcome::TokenAuthorized)
            | (TokenOutcome::TokenRejected, TokenOutcome::TokenRejected)
            | (TokenOutcome::TokenRevoked, TokenOutcome::TokenRevoked)
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
