use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;

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

    pub fn parse(content: &[u8]) -> Result<(&[u8], PrivateKey)> {
        let (content, pk) = super::super::parse_bytes(content)?;
        let (content, sk) = super::super::parse_bytes(content)?;
        let sk = Sk {
            priv_part: BigInt::from_bytes_be(Sign::Plus, &sk[..32]).into(),
            pub_part: BigInt::from_bytes_be(Sign::Plus, &sk[32..]).into(),
        };
        let wrapped = PrivateKey {
            pk: BigInt::from_bytes_be(Sign::Plus, pk).into(),
            sk,
        };
        Ok((content, wrapped))
    }
}

pub mod pubkey {
    use crate::string::BitStr;

    use super::*;

    pub fn parse(content: &[u8]) -> Result<(&[u8], BitStr)> {
        let (content, pk) = super::super::parse_bytes(content)?;
        Ok((content, BitStr::from(pk)))
    }
}
