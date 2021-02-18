/// Error handling for the library
#[derive(Debug)]
pub enum LiteSessionError {
    /// The `nonce` length is not valid as it should be of `12 bytes/96bit` length.
    /// Using a `12 characters alphanumeric string` generated from a
    /// `cryptographically secure random number(CSPRNG)` is recommended.
    NonceLengthError,
    /// The `key` length of the provided `server key` is not valid as it should be
    /// `32byte/256bit` length. Using a `32 characters alphanumeric string` generated from a
    /// `cryptographically secure random number(CSPRNG)` is recommended.
    ServerKeyLengthError,
    /// The size of the token from a user is too big as it should not be more than 1KiB in size
    /// This circumvents denial-of-service(DOS) attacks since a very large token can consume
    /// execessive resources thereby starving other requests or processes
    TokenSizeTooLarge,
    /// The provided tokens length has been tampered with or the token is corrupted
    TokenFieldsLengthError,
    /// The provided token contains invalid length `acl` fields indicating a tampered or corrupted token
    DataFieldsLengthError,
    /// The string provided was not of type `hex` even though a hex type is needed
    InvalidHexString,
    /// The destructured time in `hex` cannot be converted to a valid `TAI64N` scientific time value
    InvalidTai64NTime,
    /// The bytes provided cannot be converted to a valid `blake3::Hash`
    InvalidBytesForBlake3,
    /// The provided bytes cannot be converted to a valid UTF-8 token.
    /// This usually happens when the `key` or `nonce` used or both are invalid
    /// resulting in a bad deserialization
    FromUtf8TokenError,
}

impl core::cmp::PartialEq for LiteSessionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LiteSessionError::NonceLengthError, LiteSessionError::NonceLengthError)
            | (LiteSessionError::ServerKeyLengthError, LiteSessionError::ServerKeyLengthError)
            | (LiteSessionError::TokenSizeTooLarge, LiteSessionError::TokenSizeTooLarge)
            | (
                LiteSessionError::TokenFieldsLengthError,
                LiteSessionError::TokenFieldsLengthError,
            )
            | (LiteSessionError::DataFieldsLengthError, LiteSessionError::DataFieldsLengthError)
            | (LiteSessionError::InvalidHexString, LiteSessionError::InvalidHexString)
            | (LiteSessionError::InvalidTai64NTime, LiteSessionError::InvalidTai64NTime)
            | (LiteSessionError::InvalidBytesForBlake3, LiteSessionError::InvalidBytesForBlake3)
            | (LiteSessionError::FromUtf8TokenError, LiteSessionError::FromUtf8TokenError) => true,
            _ => false,
        }
    }
}
