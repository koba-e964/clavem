use serde::Serialize;

use crate::int::DisplayedInt;

use super::error::{Error, Result};

const HEADER: &[u8] = b"openssh-key-v1\0";

#[derive(Serialize)]
pub struct PrivPart {
    pub checksum: DisplayedInt,
    pub algo: String,
    pub content: serde_json::Value,
    pub comment: String,
}

#[derive(Serialize)]
pub struct PrivateKey {
    pub ciphername: String,
    pub kdfname: String,
    pub kdf: String,
    pub pub_part: super::pubkey::PubPart,
    pub priv_part: PrivPart,
}

pub fn parse_priv_part(content: &[u8]) -> Result<PrivPart> {
    let (content, rand0) = super::parse_u32(content)?;
    let (content, rand1) = super::parse_u32(content)?;
    if rand0 != rand1 {
        return Err(Error::ParseError);
    }
    let (content, algo) = super::parse_bytes(content)?;
    let algo = String::from_utf8(algo.to_vec())?;
    let mut wrapped = PrivPart {
        checksum: rand0.into(),
        algo: algo.clone(),
        content: serde_json::Value::String("unknown algorithm".to_string()),
        comment: "".to_string(),
    };
    if algo == "ecdsa-sha2-nistp256" {
        let (content, priv_key) = super::ecdsa::privkey::parse(content)?;
        let (content, comment) = super::parse_bytes(content)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(&priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
    }
    if algo == "ssh-dss" {
        let (content, priv_key) = super::dsa::privkey::parse(content)?;
        let (content, comment) = super::parse_bytes(content)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(&priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
    }
    if algo == "ssh-ed25519" {
        let (content, priv_key) = super::ed25519::privkey::parse(content)?;
        let (content, comment) = super::parse_bytes(content)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(&priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
    }
    if algo == "ssh-rsa" {
        let (content, priv_key) = super::rsa::privkey::parse(content)?;
        let (content, comment) = super::parse_bytes(content)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(&priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
    }
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
    let (remaining, pub_part) = super::pubkey::parse_data(pub_part)?;
    if !remaining.is_empty() {
        return Err(Error::ParseError);
    }
    let priv_part = parse_priv_part(priv_part)?;
    let wrapped = PrivateKey {
        ciphername: String::from_utf8(ciphername.to_vec())?,
        kdfname: String::from_utf8(kdfname.to_vec())?,
        kdf: String::from_utf8(kdf.to_vec())?,
        pub_part,
        priv_part,
    };
    Ok(wrapped)
}
