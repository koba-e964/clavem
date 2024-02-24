use crate::span::Span;

use self::error::{Error, Result};

pub mod dsa;
pub mod ecdsa;
pub mod ed25519;
pub mod error;
pub mod privkey;
pub mod pubkey;
pub mod rsa;

// nom-like parsing functions

fn parse_tag<'a>(content: &'a [u8], offset: usize, tag: &[u8]) -> Result<(&'a [u8], Span)> {
    if content.len() < tag.len() || &content[..tag.len()] != tag {
        return Err(Error::ParseError);
    }
    Ok((&content[tag.len()..], Span::new(offset, offset + tag.len())))
}

fn parse_u32(content: &[u8], offset: usize) -> Result<(&[u8], Span, u32)> {
    if content.len() < 4 {
        return Err(Error::ParseError);
    }
    let value = u32::from_be_bytes(<[u8; 4]>::try_from(&content[..4]).unwrap());
    Ok((&content[4..], Span::new(offset, offset + 4), value))
}

fn parse_bytes(content: &[u8], offset: usize) -> Result<(&[u8], Span, &[u8])> {
    let (content, _, len) = parse_u32(content, offset)?;
    if content.len() < len as usize {
        return Err(Error::ParseError);
    }
    Ok((
        &content[len as usize..],
        Span::new(offset, offset + 4 + len as usize),
        &content[..len as usize],
    ))
}
