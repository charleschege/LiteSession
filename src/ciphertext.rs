use crate::{LiteSessionData, SessionTokenRng};

use chacha20::{
    cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek},
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
