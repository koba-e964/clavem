use serde::Serialize;

use crate::{int::DisplayedInt, span::Span, string::BitStr};

use super::error::{Error, Result};

const HEADER: &[u8] = b"openssh-key-v1\0";

#[derive(Serialize)]
pub struct PrivPart {
    pub checksum: DisplayedInt,
    pub algo: String,
    pub content: serde_json::Value,
    pub comment: String,
    pub span: Span,
}

#[derive(Serialize)]
pub struct PrivateKey {
    pub ciphername: String,
    pub kdfname: String,
    pub kdf: BitStr,
    pub pub_part: super::pubkey::PubPart,
    pub priv_part: PrivPart,
}

pub fn parse_priv_part(content: &[u8], offset: usize) -> Result<PrivPart> {
    let (content, rand0_span, rand0) = super::parse_u32(content, offset)?;
    let (content, rand1_span, rand1) = super::parse_u32(content, rand0_span.end)?;
    if rand0 != rand1 {
        return Err(Error::ParseError);
    }
    let (content, algo_span, algo) = super::parse_bytes(content, rand1_span.end)?;
    let algo = String::from_utf8(algo.to_vec())?;
    let mut wrapped = PrivPart {
        checksum: DisplayedInt::new(rand0.into(), Span::new(rand0_span.start, rand1_span.end)),
        algo: algo.clone(),
        content: serde_json::Value::String("unknown algorithm".to_string()),
        comment: "".to_string(),
        span: Span::new(offset, content.len() + offset),
    };
    if algo == "ecdsa-sha2-nistp256" {
        let (content, priv_key_span, priv_key) =
            super::ecdsa::privkey::parse(content, algo_span.end)?;
        let (content, _comment_span, comment) = super::parse_bytes(content, priv_key_span.end)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
        wrapped.span = priv_key_span;
    }
    if algo == "ssh-dss" {
        let (content, priv_key_span, priv_key) =
            super::dsa::privkey::parse(content, algo_span.end)?;
        let (content, _comment_span, comment) = super::parse_bytes(content, priv_key_span.end)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
        wrapped.span = priv_key_span;
    }
    if algo == "ssh-ed25519" {
        let (content, priv_key_span, priv_key) =
            super::ed25519::privkey::parse(content, algo_span.end)?;
        let (content, _comment_span, comment) = super::parse_bytes(content, priv_key_span.end)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
        wrapped.span = priv_key_span;
    }
    if algo == "ssh-rsa" {
        let (content, priv_key_span, priv_key) =
            super::rsa::privkey::parse(content, algo_span.end)?;
        let (content, _comment_span, comment) = super::parse_bytes(content, priv_key_span.end)?;
        if content.len() >= 8 {
            return Err(Error::ParseError);
        }
        wrapped.content = serde_json::to_value(priv_key)?;
        wrapped.comment = String::from_utf8(comment.to_vec())?;
        wrapped.span = priv_key_span;
    }
    Ok(wrapped)
}

// Reference: https://coolaj86.com/articles/the-openssh-private-key-format/
pub fn parse(content: &[u8], offset: usize) -> Result<PrivateKey> {
    let (content, tag_span) = super::parse_tag(content, offset, HEADER)?;
    let (content, ciphername_span, ciphername) = super::parse_bytes(content, tag_span.end)?;
    let (content, kdfname_span, kdfname) = super::parse_bytes(content, ciphername_span.end)?;
    let (content, kdf_span, kdf) = super::parse_bytes(content, kdfname_span.end)?;
    let (content, numkeys_span, numkeys) = super::parse_u32(content, kdf_span.end)?;
    if numkeys != 1 {
        return Err(Error::ParseError);
    }
    let (content, pub_part_span, pub_part) = super::parse_bytes(content, numkeys_span.end)?;
    let (content, priv_part_span, priv_part) = super::parse_bytes(content, pub_part_span.end)?;
    if !content.is_empty() {
        return Err(Error::ParseError);
    }
    let (remaining, _pub_part_inner_span, pub_part_inner) =
        super::pubkey::parse_data(pub_part, pub_part_span.start + 4)?;
    if !remaining.is_empty() {
        return Err(Error::ParseError);
    }

    let mut wrapped = PrivateKey {
        ciphername: String::from_utf8(ciphername.to_vec())?,
        kdfname: String::from_utf8(kdfname.to_vec())?,
        kdf: kdf.into(),
        pub_part: pub_part_inner,
        priv_part: PrivPart {
            checksum: DisplayedInt::new(0.into(), priv_part_span),
            algo: "unknown".to_owned(),
            content: serde_json::Value::Null,
            comment: "encrypted key".to_owned(),
            span: priv_part_span,
        },
    };
    if wrapped.ciphername == "none" {
        let priv_part = parse_priv_part(priv_part, priv_part_span.start + 4)?;
        wrapped.priv_part = priv_part;
    }
    Ok(wrapped)
}
