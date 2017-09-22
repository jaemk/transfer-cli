/*!
Error type and conversions
*/
use std;
use ring;
use reqwest;
use hex;

error_chain! {
    foreign_links {
        Io(std::io::Error);
        Reqwest(reqwest::Error);
        RingUnspecified(ring::error::Unspecified);
        FromHex(hex::FromHexError);
        Utf8(std::str::Utf8Error);
    }
    errors {
        InvalidUtf8Path(s: String) {
            description("Path contains invalid utf8")
            display("InvalidUtf8Path Error: {}", s)
        }
        ConfirmationError(s: String) {
            description("Confirmation Error")
            display("ConfirmationError: {}", s)
        }
    }
}

