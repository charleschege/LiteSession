#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! #### LiteSession
//!
//! Create Session Tokens that are Resilient to Misuse and Highjacking
//!
//! This library is inspired by research [A Secure Cookie Protocol](https://github.com/charleschege/LiteSession/blob/master/Research%20Documents/cookie.pdf) paper by Liu et.al
//! which advocates for tokens that do not need to be stored in a database and are also
//! resistant to a whole class of attacks on session tokens including attacks
//! like `Volume attacks` , `Denning-Sacco Attack` and `stealing session tokens`.
//!
//! LiteSession is a token generator for secure tokens that can be used in HTTP authentication
//! headers, cookies, in place of Json Web Tokens, in IoT and  anywhere else where secure tokens
//! are needed for communication between clients and servers.
//! It provides Keyed-Hash Message Authentication tokens with associated client data in either
//! encrypted (default settings) or  unencrypted form.
//!
//! The symmetric encryption used is `ChaCha8` which is good enough,
//! refer to the paper [Too Much Crypto by Jean-Philippe Aumasson](https://github.com/charleschege/LiteSession/blob/master/Research%20Documents/Too%20much%20crypto.pdf)
//! which shows that the encryption scheme is accurate while still
//! yielding about 2.5 times the speed of its increased round `ChaCha20` option.
//! `ChaCha8` is also lightweight and fast even without hardware acceleration allowing
//! it to be used even on devices with low CPU and RAM resources.
//!
//! The algorithm is as follows:
//!
//! ```text
//!         identifier | issued | expiry | (data)k | nonce | ConfidentialityMode | Blake3HMAC( identifier | issued | expiration | data | session key, k)
//! ```
//!
//! ```text
//!         where `k = Blake3HMAC(identifier | issued | expiry | ConfidentialityMode, sk)`
//! ```
//!
//!
//! The security design used for HMAC and Encryption are:
//!
//! 1. [**TAI64N**](https://crates.io/crates/tai64) - handles issued time down to the nanosecond without the need to handle leap seconds and timezones.
//! 2. [**ChaCha8**](https://crates.io/crates/chacha20) - handles symetric encryption of the data to prevent it from being read by a party other than the server that issued the token.
//! 3. [**Blake3**](https://crates.io/crates/blake3) - a crazy fast non-cryptographic hashing algorithm used in keyed-mode to act as the  **Keyed-Hash Message Authentication Code**
//! 4. [**Nanorand**](https://crates.io/crates/nanorand) - used as a **cryptographically secure random number generator (*CSPRNG*)** with `ChaCha` mode enabled
//! 5. [**Secrecy**](https://crates.io/crates/secrecy) - used to hold the keys or token in memory to prevent them from being logged by logging tools, cloning and being moved around.
//!
//! ##### The steps to generate the token:
//!
//! 1. Generate a `random identifier`
//!
//! 2. Generate an `issued time` and `expiry time` in nanoseconds accuracy
//!
//! 3. Generate the `encryption key` to encrypt the data portion of the token using algorithm  `k = Blake3HMAC(identifier | issued | expiry | ConfidentialityMode, sk)`
//!
//!    - Create an empty string `encryption_key`
//!    - Append `identifier` to `encryption_key`
//!    - Append `issued` to `encryption_key`
//!    - Append `expiry` to `encryption_key`
//!    - Append `ConfidentialityMode` to `encryption_key`
//!    - Perform a HMAC function to the `encryption_key` using Blake3 in keyed mode and the `server_key` as the key
//!    -  Return the result of the Blake3 operation above in `hex` or as a `string`
//!
//! 4. Encrypt the data using `ChaCha8` encryption using the Blake3Hash above as the encryption key
//!
//! 5.  Return the encrypted data and `nonce`
//!
//! 6.  Perform a **Blake3Hmac** on `identifier | issued | expiry | (data)k | nonce | ConfidentialityMode`
//!
//! 7.  Generate the token:
//!
//!    - Create an empty string called `token`
//!    - Append `identifier` to `token`
//!    -  Append `issued` to `token`
//!    - Append `expiry` to `token`
//!    - Append `encrypted data` to `token`
//!    - Append `nonce` to `token`
//!    - Append `ConfidentialityMode` to `token`
//!    - Append `Blake3Hmac` to `token`
//!    - Return the token as a string or hex
//!    - The token generated is in the format `identifier⊕issued⊕expiry⊕ciphertext⊕nonce⊕confidentiality⊕hmac`
//!
//!    
//!
//! ##### Verifying the token takes the following steps
//! 1. Check if the token structure is valid
//!
//! 2.  Destructure the token into its component fields
//!
//! 3.  Compare the `expiry`  to the server's `current time` and return `SessionExpired` as the `TokenOutcome`
//!
//! 4. Compute the encryption key as follows: `k=HMAC(identifier | issued | expiry | ConfidentialityMode, sk)`
//!
//! 5.  Decrypt the encrypted data using `k`.
//!
//! 6. Compute `Blake3HMAC(identifier |issued | expiry | ciphertext | nonce | ConfidentialityMode | session key, k),`
//!
//! 7. Return `TokenOutcome::TokenAuthetic` if the token matches or `TokenOutcome::TokenRejected` if the token does not match
//!
//!    ##### NOTES:
//!
//!    The `Blake3` algorithm is used in `keyed` mode where the key is a `32byte/256bit` in length
//!    The `ChaCha8` algorithm takes a `32byte/256bit` key and `12byte/96bit nonce`
//!    `International Atomic Time(TAI)` is used for nanosecond accuracy and not having to deal with leap seconds and timezones
//!    Using the `session key` prevents `volume` and `Denning-Sacco` attacks
//!
//!
//! ### Usage
//!
//!
//! #### Creating a token
//!
//! ```rust
//! use lite_session::{LiteSessionToken, LiteSessionError, ConfidentialityMode, LiteSessionData, Role, LiteSessionMode};
//! use core::time::Duration;
//!
//! fn main() -> Result<(), LiteSessionError> {
//!     let mut token = LiteSessionToken::default();
//!
//!     let expiry = 60*60_u64;
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
//!     let session_token = "5tl726krvgmhoe1pyc4jadqs3fw09bi8⊕40000000602e51ab3a8e2d17⊕40000000603013ab3a8e2d17⊕3cf157bed212d5b34122a713ea860ec373800e5004bff1a195d603305bd5b7921d1017e70ef599bc1f7ed949bd3c66c696d74a16487f95a3f6fd⊕jrzapflsi618⊕ConfidentialityMode::High⊕4faab373d7247dfb2d50e213e5cb66e415afc22066f71c2b966fdeabb11cac64";
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
