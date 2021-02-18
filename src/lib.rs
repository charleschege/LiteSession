#![forbid(unsafe_code)]
//TODO #![deny(missing_doc_code_examples)]
#![deny(missing_docs)]

//! LiteSession is a token generator for secure tokens that can be used in
//! HTTP auth headers, cookies, in place of Json Web Tokens, in IoT and
//! anywhere else where secure tokens are needed for communication between
//! clients and servers. It provides Keyed-Hash Message authentication codes
//! with associated client data in either encrypted (default settings) or
//! unencrypted form.
//!
//! The general form of the algorithm is
//!
//! ```text
//! identifier | issued | expiry | (data)k | nonce | ConfidentialityMode | Blake3HMAC( username | issued | expiration | data | session key, k)
//!             where `k = Blake3HMAC(user | issued | expiry | ConfidentialityMode, sk)`
//! ```
//! The steps involved include:
//! 1. Generate a `random identifier`
//! 2. Generate an `issued time` and `expiry time` in nanoseconds accuracy
//! 3. generate the `encryption key` to encrypt the data portion of the token.
//! using algorithm  `k = Blake3HMAC(identifier | issued | expiry | ConfidentialityMode, sk)`
//!
//!     - Create an empty string `encryption_key`
//!     - Append `identifier` to `encryption_key`
//!     - Append `issued` to `encryption_key`
//!     - Append `expiry` to `encryption_key`
//!     - Append `ConfidentialityMode` to `encryption_key`
//!     - Perform a HMAC function to the `encryption_key` using Blake3 in keyed mode and the `server_key` as the key
//!     - Return the result of the Blake3 operation above in `hex` or as a `string`
//! 4. Encrypt the data using `ChaCha8` encryption using the Blake3Hash above as the encryption key
//! 5. Return the encrypted data and `nonce`
//! 6. Perform a Blake3Hmac on `identifier | issued | expiry | (data)k | nonce | ConfidentialityMode`
//! 7. Generate the token:
//!
//!     - Create an empty string called `token`
//!     - Append `identifier` to `token`
//!     - Append `issued` to `token`
//!     - Append `expiry` to `token`
//!     - Append `encrypted data` to `token`
//!     - Append `nonce` to `token`
//!     - Append `ConfidentialityMode` to `token`
//!     - Append `Blake3Hmac` to `token`
//!     - Return the token as a string or hex
//!
//!
//! Verifying the token takes the following steps
//!
//! 1. Check if the token structure is valid
//! 2. Destructure the token into its component fields
//! 3. Compare the `expiry`  to the server's `current time` and return `SessionExpired` as the `TokenOutcome`
//! 4. Compute the encryption key as follows: `k=HMAC(identifier | issued | expiry | ConfidentialityMode, sk)`
//! 5. Decrypt the encrypted data using `k`.
//! 6. Compute `Blake3HMAC(identifier |issued | expiry | ciphertext | nonce | ConfidentialityMode | session key, k),`
//! 7. Return `TokenOutcome::TokenAuthetic` if the token matches or `TokenOutcome::TokenRejected` if the token does not match
//!
//!
//! The `Blake3` algorithm is used in `keyed` mode where the key is a `32byte/256bit` in length
//! The `ChaCha8` algorithm takes a `32byte/256bit` key and `12byte/96bit nonce`
//! `International Atomic Time(TAI)` is used for nanosecond accuracy and not having to deal with leap seconds and timezones
//! Using the `session key` prevents `volume` and `Denning-Sacco` attacks
//!
//!
//! ### Usage
//!
//!
//! #### Creating a token
//!
//! ```rust
//! use lite_session::{LiteSessionToken, LiteSessionError, ConfidentialityMode, LiteSessionData, LiteSessionMode};
//! fn main() -> Result<(), LiteSessionError> {
//!     let mut token = LiteSessionToken::default();
//!
//!     let expiry = Duration::from_secs(60*60);
//!     token.expiry(expiry);
//!
//!     let mut data = LiteSessionData::default();
//!     data.username("foo_user");
//!     data.role(Role::SuperUser);
//!     data.tag("Foo-Tag");
//!     data.add_acl("Network-TCP");
//!     data.add_acl("Network-UDP");
//!     token.hmac_data(data);
//!     token.confidential(true);
//!     token.mode(LiteSessionMode::SessionID("foobarbaz".into()));
//!
//!     let server_key = [0_u8; 32];
//!     let session_token = token.build_secure(&server_key)?;
//!
//!     Ok(())
//! }
//! ```
//!
//!
//! #### Verifying a token
//!
//! ```rust
//! use lite_session::{LiteSessionToken, LiteSessionError, ConfidentialityMode, LiteSessionData, LiteSessionMode};
//! fn main() -> Result<(), LiteSessionError> {
//!     let server_key = [0_u8; 32];
//!
//!     let mut destructured = LiteSessionToken::default();
//!     let session_token = "FoooBar";
//!     let outcome = destructured.from_string(&server_key, &session_token)?;
//!     
//!     Ok(())
//! }
//! ````
//!

mod ciphertext;
pub use ciphertext::*;
mod data;
pub use data::*;
mod errors;
pub use errors::*;
mod global;
pub use global::*;
mod mode;
pub use mode::*;
mod token;
pub use token::*;
