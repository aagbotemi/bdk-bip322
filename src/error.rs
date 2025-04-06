use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub enum Error {
    ExtractionError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ExtractionError(e) => write!(f, "Unable to extract {}", e),
        }
    }
}
