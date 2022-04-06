use num_bigint::{BigInt, Sign};
use serde_lite::Serialize;

use crate::int::DisplayedInt;

use super::error::Result;

// https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L3602-L3617
#[derive(Serialize)]
pub struct PrivateKey {
    pub n: DisplayedInt,
    pub e: DisplayedInt,
    pub d: DisplayedInt,
    pub iqmp: DisplayedInt,
    pub p: DisplayedInt,
    pub q: DisplayedInt,
}

pub mod privkey {
    use super::*;

    pub fn parse(content: &[u8]) -> Result<(&[u8], PrivateKey)> {
        let (content, n) = super::super::parse_bytes(content)?;
        let (content, e) = super::super::parse_bytes(content)?;
        let (content, d) = super::super::parse_bytes(content)?;
        let (content, iqmp) = super::super::parse_bytes(content)?;
        let (content, p) = super::super::parse_bytes(content)?;
        let (content, q) = super::super::parse_bytes(content)?;
        let wrapped = PrivateKey {
            n: BigInt::from_bytes_be(Sign::Plus, n).into(),
            e: BigInt::from_bytes_be(Sign::Plus, e).into(),
            d: BigInt::from_bytes_be(Sign::Plus, d).into(),
            iqmp: BigInt::from_bytes_be(Sign::Plus, iqmp).into(),
            p: BigInt::from_bytes_be(Sign::Plus, p).into(),
            q: BigInt::from_bytes_be(Sign::Plus, q).into(),
        };
        Ok((content, wrapped))
    }
}
