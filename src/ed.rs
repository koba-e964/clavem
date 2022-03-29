use serde::Serialize;

use crate::error::Result;
use crate::int::PrivateInt;
use crate::string::BitStr;

#[derive(Serialize)]
pub struct EdPrivateKey {
    pub scalar: PrivateInt,
}

#[derive(Serialize)]
pub struct EdPublicKey {
    pub point: BitStr,
}

pub mod privkey {
    use asn1_rs::{FromDer, Integer, OctetString};

    use super::*;

    pub fn parse(content: &[u8]) -> Result<EdPrivateKey> {
        let (_, inner) = OctetString::from_der(content).map_err(asn1_rs::Error::from)?;
        Ok(EdPrivateKey {
            scalar: Integer::new(inner.as_cow()).into(),
        })
    }
}

pub mod pubkey {
    use asn1_rs::BitString;

    use super::*;

    pub fn parse(content: &[u8]) -> Result<EdPublicKey> {
        let point = BitString::new(0, content);
        Ok(EdPublicKey {
            point: point.into(),
        })
    }
}
