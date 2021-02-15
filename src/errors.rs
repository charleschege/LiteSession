#[derive(Debug)]
pub enum LiteSessionError {
    NonceLengthError,
    ServerKeyLengthError,
    ChaCha8DecryptionError,
    ChaCha8EncryptionError,
    TokenSizeTooLarge,
    TokenFieldsLengthError,
    DataFieldsLengthError,
    InvalidHexString,
    InvalidTai64NTime,
    InvalidBytesForBlake3,
    FromUtf8Error,
}
