use crate::{
    CipherText, ConfidentialityMode, LiteSessionData, LiteSessionError, LiteSessionMode,
    SessionTokenRng, TokenOutcome,
};

use core::time::Duration;
use std::convert::TryInto;
use tai64::TAI64N;
use timelite::LiteDuration;

/// The token strucuture that performs token operations
///
/// ```
/// use tai64::TAI64N;
/// use lite_session::{LiteSessionData, ConfidentialityMode, LiteSessionMode};
/// use blake3::Hash;
///
/// pub struct LiteSessionToken {
///     identifier: String,
///     issued: TAI64N,
///     expiry: TAI64N,
///     hmac_data: LiteSessionData,
///     confidentiality: ConfidentialityMode,
///     hmac: blake3::Hash,
///     mode: LiteSessionMode,
/// }
/// ````
#[derive(Debug)]
pub struct LiteSessionToken {
    identifier: String,
    issued: TAI64N,
    expiry: TAI64N,
    hmac_data: LiteSessionData,
    confidentiality: ConfidentialityMode,
    hmac: blake3::Hash,
    mode: LiteSessionMode,
}

impl Default for LiteSessionToken {
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

impl core::cmp::PartialEq for LiteSessionToken {
    fn eq(&self, other: &Self) -> bool {
        if self.identifier == other.identifier
            && self.issued == other.issued
            && self.expiry == other.expiry
            && self.hmac_data == other.hmac_data
            && self.hmac == other.hmac
            && self.mode == other.mode
        {
            true
        } else {
            false
        }
    }
}

impl core::clone::Clone for LiteSessionToken {
    fn clone(&self) -> Self {
        Self {
            identifier: self.identifier.clone(),
            issued: self.issued.clone(),
            expiry: self.expiry.clone(),
            hmac_data: self.hmac_data.clone(),
            confidentiality: self.confidentiality.clone(),
            hmac: self.hmac.clone(),
            mode: self.mode.clone(),
        }
    }
}

impl LiteSessionToken {
    /// Add an custom identifier for the token
    pub fn identifier(&mut self, identifier: &str) -> &mut Self {
        self.identifier = identifier.into();

        self
    }
    /// Add a custom expiry time for the token. Default exipry is 24 hours
    pub fn expiry(&mut self, expiry_in_secs: u64) -> &mut Self {
        self.expiry = self.issued + Duration::from_secs(expiry_in_secs);

        self
    }
    /// The data contained here describes the token and its capabilities
    /// as provided by `LiteSessionData` struct
    pub fn hmac_data(&mut self, data: LiteSessionData) -> &mut Self {
        self.hmac_data = data;

        self
    }
    /// Choose the security mode. Choosing `true` makes the token authenticate
    /// in high confidentiality mode by setting the field to `ConfidentialityMode::High`
    /// setting it to false sets the security mode to `ConfidentialityMode::Low`
    pub fn confidential(&mut self, bool_choice: bool) -> &mut Self {
        match bool_choice {
            true => self.confidentiality = ConfidentialityMode::High,
            false => self.confidentiality = ConfidentialityMode::Low,
        }

        self
    }
    /// Set the session mode to either use a `SessionID` or not
    pub fn mode(&mut self, mode: LiteSessionMode) -> &mut Self {
        self.mode = mode;

        self
    }

    fn compute_hmac(&self, server_key: &[u8; 32], ciphertext: &str, nonce: &str) -> blake3::Hash {
        //Blake3HMAC(identifier|issued|expiry|ciphertext|nonce|ConfidentialityMode, k)

        let issue_time = hex::encode(self.issued.to_bytes());
        let expiry_time = hex::encode(self.expiry.to_bytes());

        let mut prepare_hmac = String::default();
        prepare_hmac.push_str(&self.identifier);
        prepare_hmac.push_str(&issue_time);
        prepare_hmac.push_str(&expiry_time);
        prepare_hmac.push_str(&ciphertext);
        prepare_hmac.push_str(&nonce);
        prepare_hmac.push_str(&ConfidentialityMode::to_string(&self.confidentiality));
        let hmac = blake3::keyed_hash(&server_key, &prepare_hmac.as_bytes());

        hmac
    }
    //TODO Add a way to build a hex token instead of a string token and
    //TODO check if tis more efficient than a string token

    /// Build the token with `High Confidentiality`
    pub fn build_secure(&mut self, server_key: &[u8]) -> Result<String, LiteSessionError> {
        match server_key.len() {
            32_usize => (),
            _ => return Err(LiteSessionError::ServerKeyLengthError),
        }
        // identifier⊕issued⊕expiry⊕ciphertext⊕nonce⊕confidentiality⊕hmac
        let issue_time = hex::encode(self.issued.to_bytes());
        let expiry_time = hex::encode(self.expiry.to_bytes());

        let server_key: [u8; 32] = self.transform_key(server_key)?;
        let mut cipher_data = CipherText::default();
        let ciphertext = cipher_data.encrypt(&self.hmac_data, &self.get_key(&server_key))?;

        let hmac = self.compute_hmac(&server_key, &ciphertext.cipher, &ciphertext.nonce);
        self.hmac = hmac;
        let hmac_hex = hex::encode(&hmac.as_bytes());

        let mut token = String::default();
        token.push_str(&self.identifier);
        token.push(LiteSessionToken::separator());
        token.push_str(&issue_time);
        token.push(LiteSessionToken::separator());
        token.push_str(&expiry_time);
        token.push(LiteSessionToken::separator());
        token.push_str(&ciphertext.cipher);
        token.push(LiteSessionToken::separator());
        token.push_str(&ciphertext.nonce);
        token.push(LiteSessionToken::separator());
        token.push_str(&ConfidentialityMode::to_string(&self.confidentiality));
        token.push(LiteSessionToken::separator());
        token.push_str(&hmac_hex);

        Ok(token)
    }
    /// Destructure and autheticate a token
    pub fn from_string(
        &mut self,
        server_key: &[u8],
        token: &str,
    ) -> Result<(TokenOutcome, &Self), LiteSessionError> {
        //TODO document errors for token sizes
        if token.len() > 1024 * 1024 {
            return Err(LiteSessionError::TokenSizeTooLarge);
        }

        let fields = token.split("⊕").collect::<Vec<&str>>();
        if fields.len() != 7_usize {
            return Err(LiteSessionError::TokenFieldsLengthError);
        }

        let identifier = fields[0];
        let issued_hex = fields[1];
        let expiry_hex = fields[2];
        let ciphertext_hex = fields[3];
        let nonce = fields[4];
        let confidentiality = fields[5];
        let hmac_hex = fields[6];

        let issued = self.tai_time(issued_hex)?;
        let expiry = self.tai_time(expiry_hex)?;

        if expiry <= TAI64N::now() {
            return Ok((TokenOutcome::SessionExpired, self));
        }

        let server_key: [u8; 32] = self.transform_key(server_key)?;

        self.identifier = identifier.into();
        self.issued = issued;
        self.expiry = expiry;
        self.confidentiality = ConfidentialityMode::from_string(confidentiality);

        let mut ciphertext_bytes = match hex::decode(ciphertext_hex) {
            Ok(bytes) => bytes,
            Err(_) => return Err(LiteSessionError::InvalidHexString),
        };

        let encryption_key = self.get_key(&server_key);
        self.hmac_data = CipherText::default().decrypt(
            &encryption_key,
            &mut ciphertext_bytes,
            nonce.as_bytes(),
        )?;

        let hmac = self.compute_hmac(&server_key, ciphertext_hex, nonce);

        if hmac != self.to_hmac(&hmac_hex)? {
            return Ok((TokenOutcome::TokenRejected, self));
        } else {
            self.hmac = hmac;
        }

        Ok((TokenOutcome::TokenAuthentic, self))
    }
    /// Make a mutable `LiteSessionToken` immutable
    pub fn immutable(&mut self) -> &Self {
        self
    }

    fn transform_key(&self, server_key: &[u8]) -> Result<[u8; 32], LiteSessionError> {
        match server_key.try_into() {
            Ok(key) => Ok(key),
            Err(_) => return Err(LiteSessionError::ServerKeyLengthError),
        }
    }

    fn get_key(&self, key: &[u8; 32]) -> [u8; 32] {
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

    fn tai_time(&self, hex_str: &str) -> Result<TAI64N, LiteSessionError> {
        let tai_bytes = match hex::decode(hex_str) {
            Ok(bytes) => bytes,
            Err(_) => return Err(LiteSessionError::InvalidHexString),
        };
        match TAI64N::from_slice(&tai_bytes) {
            Ok(tai_time) => Ok(tai_time),
            Err(_) => return Err(LiteSessionError::InvalidTai64NTime),
        }
    }

    fn to_hmac(&self, hash_hex: &str) -> Result<blake3::Hash, LiteSessionError> {
        let hash_bytes = match hex::decode(hash_hex) {
            Err(_) => return Err(LiteSessionError::InvalidHexString),
            Ok(bytes) => bytes,
        };
        let hash_array: [u8; blake3::OUT_LEN] = match hash_bytes[..].try_into() {
            Err(_) => return Err(LiteSessionError::InvalidBytesForBlake3),
            Ok(bytes) => bytes,
        };
        let hash: blake3::Hash = hash_array.into();

        Ok(hash)
    }

    fn separator() -> char {
        '⊕'
    }
}

#[cfg(test)]
mod token_tests {
    use super::LiteSessionToken;
    use crate::{
        ConfidentialityMode, LiteSessionData, LiteSessionError, LiteSessionMode, Role, TokenOutcome,
    };

    #[test]
    fn tokens() -> Result<(), LiteSessionError> {
        let mut token = LiteSessionToken::default();
        assert_eq!(token.identifier.len(), 32_usize);

        let change_expiry = timelite::LiteDuration::hours(32);
        token.expiry(change_expiry);
        assert_eq!(
            token.expiry,
            token.issued + core::time::Duration::from_secs(change_expiry)
        );

        let mut data = LiteSessionData::default();
        data.username("foo_user");
        data.role(Role::SuperUser);
        data.tag("Foo-Tag");
        data.add_acl("Network-TCP");
        data.add_acl("Network-UDP");
        token.hmac_data(data.clone());
        assert_eq!(token.hmac_data, data);

        token.confidential(false);
        assert_eq!(token.confidentiality, ConfidentialityMode::Low);
        token.confidential(true);
        assert_eq!(token.confidentiality, ConfidentialityMode::High);

        token.mode(LiteSessionMode::SessionID("foobarbaz".into()));
        assert_eq!(token.mode, LiteSessionMode::SessionID("foobarbaz".into()));
        assert_ne!(token.mode, LiteSessionMode::SessionID("garbage".into()));
        token.mode(LiteSessionMode::Passive);
        assert_eq!(token.mode, LiteSessionMode::Passive);

        {
            let bad_key = [0_u8; 5];
            assert_eq!(
                token.build_secure(&bad_key),
                Err(LiteSessionError::ServerKeyLengthError)
            );
        }

        {
            let server_key = [0_u8; 32];
            let session_token = token.build_secure(&server_key)?;

            let mut destructured = LiteSessionToken::default();
            let outcome = destructured.from_string(&server_key, &session_token)?;

            assert_eq!(outcome, (TokenOutcome::TokenAuthentic, token.immutable()));
        }

        {
            let server_key = [0_u8; 32];
            let session_token = token.build_secure(&server_key)?;

            let mut destructured = LiteSessionToken::default();
            let outcome = destructured.from_string(&[1_u8; 32], &session_token);

            assert_eq!(outcome, Err(LiteSessionError::FromUtf8TokenError));
        }

        Ok(())
    }
}
