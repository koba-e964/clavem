use serde::Serialize;

use crate::error::Result;
use crate::int::DisplayedInt;

#[derive(Serialize)]
pub struct EdPrivateKey {
    pub scalar: DisplayedInt,
}

#[derive(Serialize)]
pub struct EdPublicKey {
    pub point: DisplayedInt,
}

pub mod privkey {
    use asn1_rs::{FromDer, OctetString};

    use super::*;

    pub fn parse(content: &[u8]) -> Result<EdPrivateKey> {
        let (_, inner) = OctetString::from_der(content).map_err(asn1_rs::Error::from)?;
        let scalar = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, inner.as_cow());
        Ok(EdPrivateKey {
            scalar: scalar.into(),
        })
    }
}

pub mod pubkey {
    use super::*;

    pub fn parse(content: &[u8]) -> Result<EdPublicKey> {
        let point = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, content);
        Ok(EdPublicKey {
            point: point.into(),
        })
    }
}
