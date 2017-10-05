/*!
Error type and conversions
*/
use std;
use ring;
use reqwest;
use hex;
#[cfg(feature="update")]
use self_update;


error_chain! {
    foreign_links {
        Io(std::io::Error);
        Reqwest(reqwest::Error);
        RingUnspecified(ring::error::Unspecified);
        FromHex(hex::FromHexError);
        Utf8(std::str::Utf8Error);
        EnvVar(std::env::VarError);
        Update(self_update::errors::Error) #[cfg(feature="update")];
    }
    errors {
        InvalidUtf8Path(s: String) {
            description("Path contains invalid utf8")
            display("InvalidUtf8Path Error: {}", s)
        }
        PathError(s: &'static str) {
            description("Path Error")
            display("PathError: {}", s)
        }
    }
}

