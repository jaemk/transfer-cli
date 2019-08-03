/*!
Error type and conversions
*/
use base64;
use hex;
use reqwest;
#[cfg(feature = "update")]
use self_update;
use std;

error_chain! {
    foreign_links {
        Io(std::io::Error);
        Reqwest(reqwest::Error);
        FromHex(hex::FromHexError);
        Utf8(std::str::Utf8Error);
        Utf8String(std::string::FromUtf8Error);
        EnvVar(std::env::VarError);
        Base64Decode(base64::DecodeError);
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
        Crypto(s: String) {
            description("crypto error")
            display("CryptoError: {}", s)
        }
    }
}
