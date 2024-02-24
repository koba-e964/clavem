use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;
use crate::span::Span;

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

// https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L2410-L2423
#[derive(Serialize)]
pub struct PublicKey {
    pub e: DisplayedInt,
    pub n: DisplayedInt,
}

pub mod privkey {
    use super::*;

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, PrivateKey)> {
        let (content, n_span, n) = super::super::parse_bytes(content, offset)?;
        let (content, e_span, e) = super::super::parse_bytes(content, n_span.end)?;
        let (content, d_span, d) = super::super::parse_bytes(content, e_span.end)?;
        let (content, iqmp_span, iqmp) = super::super::parse_bytes(content, d_span.end)?;
        let (content, p_span, p) = super::super::parse_bytes(content, iqmp_span.end)?;
        let (content, q_span, q) = super::super::parse_bytes(content, p_span.end)?;
        let wrapped = PrivateKey {
            n: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, n), n_span),
            e: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, e), e_span),
            d: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, d), d_span),
            iqmp: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, iqmp), iqmp_span),
            p: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, p), p_span),
            q: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, q), q_span),
        };
        Ok((content, Span::new(offset, q_span.end), wrapped))
    }
}

pub mod pubkey {
    use super::*;

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, PublicKey)> {
        let (content, e_span, e) = super::super::parse_bytes(content, offset)?;
        let (content, n_span, n) = super::super::parse_bytes(content, e_span.end)?;
        let wrapped = PublicKey {
            e: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, e), e_span),
            n: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, n), n_span),
        };
        Ok((content, Span::new(e_span.start, n_span.end), wrapped))
    }
}
