use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;
use crate::span::Span;

use super::error::Result;

#[derive(Serialize)]
pub struct Sk {
    pub priv_part: DisplayedInt,
    pub pub_part: DisplayedInt,
}

// https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L3633-L3637
#[derive(Serialize)]
pub struct PrivateKey {
    pub pk: DisplayedInt,
    pub sk: Sk,
}

pub mod privkey {
    use super::*;

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, PrivateKey)> {
        let (content, pk_span, pk) = super::super::parse_bytes(content, offset)?;
        let (content, sk_span, sk) = super::super::parse_bytes(content, pk_span.end)?;
        let sk = Sk {
            priv_part: DisplayedInt::new(
                BigInt::from_bytes_be(Sign::Plus, &sk[..32]),
                Span {
                    start: sk_span.start + 4,
                    end: sk_span.start + 36,
                },
            ),
            pub_part: DisplayedInt::new(
                BigInt::from_bytes_be(Sign::Plus, &sk[32..]),
                Span {
                    start: sk_span.start + 36,
                    ..sk_span
                },
            ),
        };
        let wrapped = PrivateKey {
            pk: DisplayedInt::new(BigInt::from_bytes_be(Sign::Plus, pk), pk_span),
            sk,
        };
        Ok((content, Span::new(offset, sk_span.end), wrapped))
    }
}

pub mod pubkey {
    use crate::string::BitStr;

    use super::*;

    pub fn parse(content: &[u8], offset: usize) -> Result<(&[u8], Span, BitStr)> {
        let (content, pk_span, pk) = super::super::parse_bytes(content, offset)?;
        Ok((content, pk_span, BitStr::from(pk)))
    }
}
