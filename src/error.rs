#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("JSON serialization failed")]
    JsonSerError(
        #[from]
        #[source]
        serde_json::Error,
    ),
    #[error("Input is invalid")]
    InvalidInputError,
    #[error("Parsing failed")]
    ParseError,
    #[error("ASN.1 parsing failed")]
    Asn1Error(
        #[from]
        #[source]
        asn1_rs::Error,
    ),
}

pub type Result<T> = std::result::Result<T, Error>;
