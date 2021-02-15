use crate::{
    CipherText, ConfidentialityMode, LiteSessionData, LiteSessionError, LiteSessionMode,
    SessionTokenRng, TokenOutcome,
};

use core::time::Duration;
use std::convert::TryInto;
use tai64::TAI64N;
use timelite::LiteDuration;

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

impl LiteSessionToken {
    pub fn identifier(&mut self, identifier: &str) -> &mut Self {
        self.identifier = identifier.into();

        self
    }

    pub fn expiry(&mut self, expiry_in_secs: u64) -> &mut Self {
        self.expiry = self.issued + Duration::from_secs(expiry_in_secs);

        self
    }

    pub fn hmac_data(&mut self, data: LiteSessionData) -> &mut Self {
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
        // identifier⊕issued⊕expiry⊕ciphertext⊕nonce⊕confidentiality⊕hmac
        let issue_time = hex::encode(self.issued.to_bytes());
        let expiry_time = hex::encode(self.expiry.to_bytes());

        let mut cipher_data = CipherText::default();
        let ciphertext = cipher_data.encrypt(&self.hmac_data, &self.get_key(key));

        //Blake3HMAC(identifier|issued|expiry|ciphertext|nonce|ConfidentialityMode, k)
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

        token
    }
    pub fn from_string(
        &mut self,
        server_key: &[u8; 32],
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

        //Blake3HMAC(identifier|issued|expiry|ciphertext|nonce|ConfidentialityMode, k)
        let mut prepare_hmac = String::default();
        prepare_hmac.push_str(&identifier);
        prepare_hmac.push_str(&issued_hex);
        prepare_hmac.push_str(&expiry_hex);
        prepare_hmac.push_str(&ciphertext_hex);
        prepare_hmac.push_str(&nonce);
        prepare_hmac.push_str(&confidentiality);
        let hmac = blake3::keyed_hash(server_key, &prepare_hmac.as_bytes());

        if hmac != self.to_hmac(hmac_hex)? {
            return Ok((TokenOutcome::TokenRejected, self));
        } else {
            dbg!("GOOD HMAC");
        }

        self.identifier = identifier.into();
        self.issued = issued;
        self.expiry = expiry;
        self.confidentiality = ConfidentialityMode::from_string(confidentiality);
        self.hmac = self.to_hmac(hmac_hex)?;

        let mut ciphertext_bytes = match hex::decode(ciphertext_hex) {
            Ok(bytes) => bytes,
            Err(_) => return Err(LiteSessionError::InvalidHexString),
        };

        self.hmac_data = CipherText::default().decrypt(
            &self.get_key(server_key),
            &mut ciphertext_bytes,
            nonce.as_bytes(),
        )?;

        Ok((TokenOutcome::TokenAuthentic, self))
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
