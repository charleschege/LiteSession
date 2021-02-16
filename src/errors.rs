#[derive(Debug)]
pub enum LiteSessionError {
    NonceLengthError,
    ServerKeyLengthError,
    TokenSizeTooLarge,
    TokenFieldsLengthError,
    DataFieldsLengthError,
    InvalidHexString,
    InvalidTai64NTime,
    InvalidBytesForBlake3,
    FromUtf8TokenError,
    To32ByteKeyError,
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
            | (LiteSessionError::FromUtf8TokenError, LiteSessionError::FromUtf8TokenError)
            | (LiteSessionError::To32ByteKeyError, LiteSessionError::To32ByteKeyError) => true,
            _ => false,
        }
    }
}
