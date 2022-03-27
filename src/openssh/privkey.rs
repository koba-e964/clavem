use num_bigint::{BigInt, Sign};
use serde::Serialize;

use crate::int::DisplayedInt;

use super::error::{Error, Result};

const HEADER: &[u8] = b"openssh-key-v1\0";

#[derive(Serialize)]
pub struct PrivPart {
    pub algo: String,
    // https://github.com/openssh/openssh-portable/blob/V_8_9_P1/sshkey.c#L3602-L3617
    pub n: DisplayedInt,
    pub e: DisplayedInt,
    pub d: DisplayedInt,
    pub iqmp: DisplayedInt,
    pub p: DisplayedInt,
    pub q: DisplayedInt,
    pub comment: String,
}

#[derive(Serialize)]
pub struct PrivateKey {
    pub ciphername: String,
    pub kdfname: String,
    pub kdf: String,
    pub pub_part: (),
    pub priv_part: PrivPart,
}

pub fn parse_priv_part(content: &[u8]) -> Result<PrivPart> {
    let (content, rand0) = super::parse_u32(content)?;
    let (content, rand1) = super::parse_u32(content)?;
    if rand0 != rand1 {
        return Err(Error::ParseError);
    }
    let (content, algo) = super::parse_bytes(content)?;
    let (content, n) = super::parse_bytes(content)?;
    let (content, e) = super::parse_bytes(content)?;
    let (content, d) = super::parse_bytes(content)?;
    let (content, iqmp) = super::parse_bytes(content)?;
    let (content, p) = super::parse_bytes(content)?;
    let (content, q) = super::parse_bytes(content)?;
    let (content, comment) = super::parse_bytes(content)?;
    if content.len() >= 8 {
        return Err(Error::ParseError);
    }
    let wrapped = PrivPart {
        algo: String::from_utf8(algo.to_vec())?,
        n: BigInt::from_bytes_be(Sign::Plus, n).into(),
        e: BigInt::from_bytes_be(Sign::Plus, e).into(),
        d: BigInt::from_bytes_be(Sign::Plus, d).into(),
        iqmp: BigInt::from_bytes_be(Sign::Plus, iqmp).into(),
        p: BigInt::from_bytes_be(Sign::Plus, p).into(),
        q: BigInt::from_bytes_be(Sign::Plus, q).into(),
        comment: String::from_utf8(comment.to_vec())?,
    };
    Ok(wrapped)
}

// Reference: https://coolaj86.com/articles/the-openssh-private-key-format/
pub fn parse(content: &[u8]) -> Result<PrivateKey> {
    let content = super::parse_tag(content, HEADER)?;
    let (content, ciphername) = super::parse_bytes(content)?;
    let (content, kdfname) = super::parse_bytes(content)?;
    let (content, kdf) = super::parse_bytes(content)?;
    let (content, numkeys) = super::parse_u32(content)?;
    if numkeys != 1 {
        return Err(Error::ParseError);
    }
    let (content, pub_part) = super::parse_bytes(content)?;
    let (content, priv_part) = super::parse_bytes(content)?;
    if !content.is_empty() {
        return Err(Error::ParseError);
    }
    let priv_part = parse_priv_part(priv_part)?;
    let wrapped = PrivateKey {
        ciphername: String::from_utf8(ciphername.to_vec())?,
        kdfname: String::from_utf8(kdfname.to_vec())?,
        kdf: String::from_utf8(kdf.to_vec())?,
        pub_part: (),
        priv_part,
    };
    Ok(wrapped)
}
