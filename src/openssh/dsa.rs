use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;

use super::error::Result;

// https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L3495-L3514
#[derive(Serialize)]
pub struct PrivateKey {
    pub p: DisplayedInt,
    pub q: DisplayedInt,
    pub g: DisplayedInt,
    pub pub_key: DisplayedInt,
    pub priv_key: DisplayedInt,
}

// https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L2438-L2459
#[derive(Serialize)]
pub struct PublicKey {
    pub p: DisplayedInt,
    pub q: DisplayedInt,
    pub g: DisplayedInt,
    pub pub_key: DisplayedInt,
}

pub mod privkey {
    use super::*;

    pub fn parse(content: &[u8]) -> Result<(&[u8], PrivateKey)> {
        let (content, p) = super::super::parse_bytes(content)?;
        let (content, q) = super::super::parse_bytes(content)?;
        let (content, g) = super::super::parse_bytes(content)?;
        let (content, pub_key) = super::super::parse_bytes(content)?;
        let (content, priv_key) = super::super::parse_bytes(content)?;

        let wrapped = PrivateKey {
            p: BigInt::from_bytes_be(Sign::Plus, p).into(),
            q: BigInt::from_bytes_be(Sign::Plus, q).into(),
            g: BigInt::from_bytes_be(Sign::Plus, g).into(),
            pub_key: BigInt::from_bytes_be(Sign::Plus, pub_key).into(),
            priv_key: BigInt::from_bytes_be(Sign::Plus, priv_key).into(),
        };
        Ok((content, wrapped))
    }
}

pub mod pubkey {
    use super::*;

    pub fn parse(content: &[u8]) -> Result<(&[u8], PublicKey)> {
        let (content, p) = super::super::parse_bytes(content)?;
        let (content, q) = super::super::parse_bytes(content)?;
        let (content, g) = super::super::parse_bytes(content)?;
        let (content, pub_key) = super::super::parse_bytes(content)?;

        let wrapped = PublicKey {
            p: BigInt::from_bytes_be(Sign::Plus, p).into(),
            q: BigInt::from_bytes_be(Sign::Plus, q).into(),
            g: BigInt::from_bytes_be(Sign::Plus, g).into(),
            pub_key: BigInt::from_bytes_be(Sign::Plus, pub_key).into(),
        };
        Ok((content, wrapped))
    }
}
