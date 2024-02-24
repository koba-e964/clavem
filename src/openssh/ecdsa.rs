use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;
use crate::span::Span;

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

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, PrivateKey)> {
        let (content, curve_span, curve) = super::super::parse_bytes(content, offset)?;
        let (content, eckey_span, eckey) = super::super::parse_bytes(content, curve_span.end)?;
        let (content, exponent_span, exponent) =
            super::super::parse_bytes(content, eckey_span.end)?;
        let wrapped = PrivateKey {
            curve: String::from_utf8(curve.to_vec())?,
            eckey: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, eckey), eckey_span),
            exponent: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, exponent), exponent_span),
        };
        Ok((content, Span::new(offset, exponent_span.end), wrapped))
    }
}

pub mod pubkey {
    use super::*;

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, PublicKey)> {
        let (content, curve_span, curve) = super::super::parse_bytes(content, offset)?;
        let (content, eckey_span, eckey) = super::super::parse_bytes(content, curve_span.end)?;
        let wrapped = PublicKey {
            curve: String::from_utf8(curve.to_vec())?,
            eckey: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, eckey), eckey_span),
        };
        Ok((content, Span::new(offset, eckey_span.end), wrapped))
    }
}
