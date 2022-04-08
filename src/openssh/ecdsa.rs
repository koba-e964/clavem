use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;

use super::error::Result;

// https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L3527-L3542
#[derive(Serialize)]
pub struct PrivateKey {
    pub curve: String,
    pub eckey: DisplayedInt,
    pub exponent: DisplayedInt,
}

// https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L2473-L2501
#[derive(Serialize)]
pub struct PublicKey {
    pub curve: String,
    pub eckey: DisplayedInt,
}

pub mod privkey {
    use super::*;

    pub fn parse(content: &[u8]) -> Result<(&[u8], PrivateKey)> {
        let (content, curve) = super::super::parse_bytes(content)?;
        let (content, eckey) = super::super::parse_bytes(content)?;
        let (content, exponent) = super::super::parse_bytes(content)?;
        let wrapped = PrivateKey {
            curve: String::from_utf8(curve.to_vec())?,
            eckey: BigInt::from_bytes_be(Sign::Plus, eckey).into(),
            exponent: BigInt::from_bytes_be(Sign::Plus, exponent).into(),
        };
        Ok((content, wrapped))
    }
}

pub mod pubkey {
    use super::*;

    pub fn parse(content: &[u8]) -> Result<(&[u8], PublicKey)> {
        let (content, curve) = super::super::parse_bytes(content)?;
        let (content, eckey) = super::super::parse_bytes(content)?;
        let wrapped = PublicKey {
            curve: String::from_utf8(curve.to_vec())?,
            eckey: BigInt::from_bytes_be(Sign::Plus, eckey).into(),
        };
        Ok((content, wrapped))
    }
}
