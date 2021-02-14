use arrayvec::ArrayString;
use chacha20::{
    cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek},
    ChaCha8, Key, Nonce,
};
use core::{
    fmt::{self, Debug, Display},
    time::Duration,
};
use nanorand::{ChaCha, RNG};
use tai64::TAI64N;
use timelite::LiteDuration;

fn main() {
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Foo {
        Bar,
        Baz,
    };

    impl Display for Foo {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Bar => write!(f, "{}", Self::Bar),
                Self::Baz => write!(f, "{}", Self::Baz),
            }
        }
    }
    let mut litesession = LiteSessionData::default();
    litesession
        .username("x43")
        .role(Role::SuperUser)
        .tag("WASI-Container")
        .add_acl(Foo::Bar)
        .add_acl(Foo::Baz);

    dbg!(&litesession);

    //litesession.remove_acl(Foo::Baz);
    dbg!(&litesession);

    let server_key = [0; 32];

    let mut token = LiteSessionToken::default();
    token
        .expiry(timelite::LiteDuration::hours(12))
        .hmac_data(litesession)
        .confidential(true)
        .mode(LiteSessionMode::Passive);

    dbg!(&token);
    dbg!(token.build_secure(&server_key));
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
pub struct LiteSessionToken<T> {
    identifier: String,
    issued: TAI64N,
    expiry: TAI64N,
    hmac_data: LiteSessionData<T>,
    confidentiality: ConfidentialityMode,
    hmac: blake3::Hash,
    mode: LiteSessionMode,
}

impl<T> Default for LiteSessionToken<T>
where
    T: core::fmt::Display + core::fmt::Debug + core::cmp::Ord,
{
    fn default() -> Self {
        let now = TAI64N::now();
        let default_expiry = LiteDuration::hours(24);
        let hmac_default = blake3::hash(b"");

        Self {
            identifier: SessionTokenRng::alphanumeric(),
            issued: now,
            expiry: now + Duration::from_secs(default_expiry),
            hmac_data: LiteSessionData::default(),
            confidentiality: ConfidentialityMode::default(),
            hmac: hmac_default,
            mode: LiteSessionMode::Passive,
        }
    }
}

impl<T> LiteSessionToken<T>
where
    T: core::fmt::Display + core::fmt::Debug + core::cmp::Ord,
{
    pub fn identifier(&mut self, identifier: &str) -> &mut Self {
        self.identifier = identifier.into();

        self
    }

    pub fn expiry(&mut self, expiry_in_secs: u64) -> &mut Self {
        self.expiry = self.issued + Duration::from_secs(expiry_in_secs);

        self
    }

    pub fn hmac_data(&mut self, data: LiteSessionData<T>) -> &mut Self {
        self.hmac_data = data;

        self
    }

    pub fn confidential(&mut self, bool_choice: bool) -> &mut Self {
        match bool_choice {
            true => self.confidentiality = ConfidentialityMode::High,
            false => self.confidentiality = ConfidentialityMode::Low,
        }

        self
    }

    pub fn mode(&mut self, mode: LiteSessionMode) -> &mut Self {
        self.mode = mode;

        self
    }

    pub fn build_secure(&self, key: &[u8; 32]) -> String {
        // identifier⊕issued⊕expiry⊕cipher_text⊕nonce⊕confidentiality⊕hmac
        let issue_time = hex::encode(self.issued.to_bytes());
        let expiry_time = hex::encode(self.expiry.to_bytes());

        let mut cipher_data = CipherText::default();
        let ciphertext = cipher_data.encrypt(&self.hmac_data, &self.get_key(key));

        //Blake3HMAC(identifier|issued|expiry|cipher_text|nonce|ConfidentialityMode, k)
        let mut prepare_hmac = String::default();
        prepare_hmac.push_str(&self.identifier);
        prepare_hmac.push_str(&issue_time);
        prepare_hmac.push_str(&expiry_time);
        prepare_hmac.push_str(&ciphertext.cipher);
        prepare_hmac.push_str(&ciphertext.nonce);
        prepare_hmac.push_str(&ConfidentialityMode::to_string(&self.confidentiality));
        let hmac = blake3::keyed_hash(key, &prepare_hmac.as_bytes());
        let hmac_hex = hex::encode(&hmac.as_bytes());

        let mut token = String::default();
        token.push_str(&self.identifier);
        token.push(LiteSessionToken::<T>::separator());
        token.push_str(&issue_time);
        token.push(LiteSessionToken::<T>::separator());
        token.push_str(&expiry_time);
        token.push(LiteSessionToken::<T>::separator());
        token.push_str(&ciphertext.cipher);
        token.push(LiteSessionToken::<T>::separator());
        token.push_str(&ciphertext.nonce);
        token.push(LiteSessionToken::<T>::separator());
        token.push_str(&ConfidentialityMode::to_string(&self.confidentiality));
        token.push(LiteSessionToken::<T>::separator());
        token.push_str(&hmac_hex);

        token
    }

    fn get_key<'a>(&self, key: &[u8; 32]) -> [u8; 32] {
        let mut raw_key = String::default();

        let identifier = self.identifier.clone();
        let issued = hex::encode(self.issued.to_bytes());
        let expiry = hex::encode(self.expiry.to_bytes());
        let confidentiality = ConfidentialityMode::to_string(&self.confidentiality);

        raw_key.push_str(&identifier);
        raw_key.push_str(&issued);
        raw_key.push_str(&expiry);
        raw_key.push_str(&confidentiality);
        let encryption_key = blake3::keyed_hash(key, raw_key.as_bytes());

        encryption_key.as_bytes().clone()
    }

    fn separator() -> char {
        '⊕'
    }
}

//TODO
//Add arrayvec for fixed capacity arrays for stack allocation
// Add secrecy and zeroize to safely hold the server key in memory

#[derive(Debug)]
pub struct CipherText {
    cipher: CipherHex, //FIXME remove allocations with `ArrayVec`
    nonce: String,     //FIXME to secrecy
}

type CipherHex = String;

impl Default for CipherText {
    fn default() -> Self {
        Self {
            cipher: CipherHex::default(),
            nonce: String::default(),
        }
    }
}

impl CipherText {
    pub fn encrypt<T: core::fmt::Debug + core::fmt::Display + core::cmp::Ord>(
        &mut self,
        ls_data: &LiteSessionData<T>,
        key: &[u8], //TODO use secrecy
    ) -> &Self {
        let nonce_string = SessionTokenRng::nonce();

        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(&nonce_string.as_bytes());

        let mut cipher = ChaCha8::new(&key, &nonce);
        let mut cipher_text = ls_data.build().into_bytes();
        cipher.apply_keystream(&mut cipher_text);

        let cipher_hex = hex::encode(cipher_text);

        self.cipher = cipher_hex;
        self.nonce = nonce_string;

        self
    }
}

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
pub struct LiteSessionData<T> {
    username: String,
    role: Role,
    tag: Option<String>,
    acl: Vec<T>,
}

impl<T> Default for LiteSessionData<T> {
    fn default() -> Self {
        Self {
            username: String::default(),
            role: Role::default(),
            tag: Option::default(),
            acl: Vec::default(),
        }
    }
}

impl<T> LiteSessionData<T>
where
    T: core::fmt::Display + core::fmt::Debug + core::cmp::Ord,
{
    pub fn username(&mut self, value: &str) -> &mut Self {
        self.username = value.into();

        self
    }

    pub fn role(&mut self, role: Role) -> &mut Self {
        self.role = role;

        self
    }

    pub fn tag(&mut self, tag: &str) -> &mut Self {
        self.tag = Some(tag.into());

        self
    }

    pub fn add_acl(&mut self, resourse: T) -> &mut Self {
        self.acl.push(resourse.into());

        self
    }

    pub fn remove_acl(&mut self, resource: T) -> Option<&mut Self> {
        match self.acl.binary_search(&resource.into()) {
            Ok(index) => {
                self.acl.remove(index);
                Some(self)
            }
            Err(_) => None,
        }
    }

    pub fn build(&self) -> String {
        let mut acl_token = String::default();
        let ls_separator = '⥂';
        let acl_separator = '⇅';
        let mut acl_list = String::default();

        acl_token.push_str(&self.username);
        acl_token.push(ls_separator);
        acl_token.push_str(&Role::to_string(&self.role));
        acl_token.push(ls_separator);

        match &self.tag {
            None => (),
            Some(tag) => acl_token.push_str(&tag),
        }

        let initial = &self.acl[0];
        acl_list.push_str(&format!("{:?}", initial));
        self.acl.iter().skip(1).for_each(|item| {
            acl_list.push(acl_separator);
            acl_list.push_str(&format!("{:?}", item))
        });
        acl_token.push(ls_separator);
        acl_token.push_str(&acl_list);

        acl_token
    }
}

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
