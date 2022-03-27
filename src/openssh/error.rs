#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("JSON serialization failed")]
    JsonSerError(
        #[from]
        #[source]
        serde_json::Error,
    ),
    #[error("Parsing failed")]
    ParseError,
    #[error("UTF-8 conversion failed")]
    UTF8ConversionError(
        #[from]
        #[source]
        std::string::FromUtf8Error,
    ),
}

pub type Result<T> = std::result::Result<T, Error>;