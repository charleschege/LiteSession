use crate::{LiteSessionData, LiteSessionError, SessionTokenRng};

use chacha20::{
    cipher::{NewStreamCipher, StreamCipher, SyncStreamCipher, SyncStreamCipherSeek},
    ChaCha8, Key, Nonce,
};
use core::fmt::Debug;

#[derive(Debug)]
pub struct CipherText {
    pub(crate) cipher: CipherHex, //FIXME remove allocations with `ArrayVec`
    pub(crate) nonce: String,     //FIXME to secrecy
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
    pub fn encrypt(
        &mut self,
        ls_data: &LiteSessionData,
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

    pub fn decrypt(
        &self,
        key: &[u8], //TODO use secrecy
        mut ciphertext: &mut [u8],
        nonce: &[u8],
    ) -> Result<LiteSessionData, LiteSessionError> {
        if key.len() != 32 {
            return Err(LiteSessionError::ServerKeyLengthError);
        }

        if nonce.len() != 12 {
            return Err(LiteSessionError::NonceLengthError);
        }

        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        let mut cipher = ChaCha8::new(&key, &nonce);
        cipher.seek(0);
        cipher.decrypt(&mut ciphertext);

        let raw_data = match String::from_utf8(ciphertext.to_vec()) {
            Ok(data) => data,
            Err(_) => return Err(LiteSessionError::FromUtf8Error),
        };

        LiteSessionData::default().destructure(&raw_data)
    }
}
