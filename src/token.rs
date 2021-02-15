use crate::{
    CipherText, ConfidentialityMode, LiteSessionData, LiteSessionError, LiteSessionMode,
    SessionTokenRng,
};

use core::time::Duration;
use tai64::TAI64N;
use timelite::LiteDuration;

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
    pub fn from_string(&mut self, token: &String) -> Result<&Self, LiteSessionError> {
        //TODO document errors for token sizes
        if token.len() > 1024 * 1024 {
            return Err(LiteSessionError::TokenSizeTooLarge);
        }

        let fields = token.split("⊕").collect::<Vec<&str>>();
        if fields.len() != 7_usize {
            return Err(LiteSessionError::TokenFieldsError);
        }

        let identifier = fields[0];
        let issued = fields[1];
        let expiry = fields[2];
        let ciphertext = fields[3];
        let nonce = fields[4];
        let confidentiality = fields[5];
        let hmac = fields[6];

        Ok(self) //FIXME return actual data
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
