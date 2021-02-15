use core::fmt::{self, Debug, Display};

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

fn main() {
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Foo {
        Bar,
        Baz,
    };

    impl Display for Foo {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Bar => write!(f, "{}", Self::Bar),
                Self::Baz => write!(f, "{}", Self::Baz),
            }
        }
    }
    let mut litesession = LiteSessionData::default();
    litesession
        .username("x43")
        .role(Role::SuperUser)
        .tag("WASI-Container")
        .add_acl(Foo::Bar)
        .add_acl(Foo::Baz);

    dbg!(&litesession);

    //litesession.remove_acl(Foo::Baz);
    dbg!(&litesession);

    let server_key = [0; 32];

    let mut token = LiteSessionToken::default();
    token
        .expiry(timelite::LiteDuration::hours(12))
        .hmac_data(litesession)
        .confidential(true)
        .mode(LiteSessionMode::Passive);

    dbg!(&token);
    dbg!(token.build_secure(&server_key));
}

//TODO
//Add arrayvec for fixed capacity arrays for stack allocation
// Add secrecy and zeroize to safely hold the server key in memory
