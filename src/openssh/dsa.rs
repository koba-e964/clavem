use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;
use crate::span::Span;

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

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, PrivateKey)> {
        let (content, p_span, p) = super::super::parse_bytes(content, offset)?;
        let (content, q_span, q) = super::super::parse_bytes(content, p_span.end)?;
        let (content, g_span, g) = super::super::parse_bytes(content, q_span.end)?;
        let (content, pub_key_span, pub_key) = super::super::parse_bytes(content, g_span.end)?;
        let (content, priv_key_span, priv_key) =
            super::super::parse_bytes(content, pub_key_span.end)?;

        let wrapped = PrivateKey {
            p: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, p), p_span),
            q: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, q), q_span),
            g: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, g), g_span),
            pub_key: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, pub_key), pub_key_span),
            priv_key: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, priv_key), priv_key_span),
        };
        Ok((content, Span::new(offset, priv_key_span.end), wrapped))
    }
}

pub mod pubkey {
    use super::*;

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, PublicKey)> {
        let (content, p_span, p) = super::super::parse_bytes(content, offset)?;
        let (content, q_span, q) = super::super::parse_bytes(content, p_span.end)?;
        let (content, g_span, g) = super::super::parse_bytes(content, q_span.end)?;
        let (content, pub_key_span, pub_key) = super::super::parse_bytes(content, g_span.end)?;

        let wrapped = PublicKey {
            p: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, p), p_span),
            q: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, q), q_span),
            g: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, g), g_span),
            pub_key: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, pub_key), pub_key_span),
        };
        Ok((content, Span::new(offset, pub_key_span.end), wrapped))
    }
}
