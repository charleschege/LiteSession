#[derive(Debug)]
pub enum LiteSessionError {
    NonceTooShort,
    NonceTooLong,
    ServerKeyTooShort,
    ServerKeyTooLong,
    ChaCha8DecryptionError,
    ChaCha8EncryptionError,
    TokenSizeTooLarge,
    TokenFieldsError,
}
