use self::error::{Error, Result};

pub mod dsa;
pub mod error;
pub mod privkey;
pub mod rsa;

// nom-like parsing functions

fn parse_tag<'a>(content: &'a [u8], tag: &[u8]) -> Result<&'a [u8]> {
    if content.len() < tag.len() || &content[..tag.len()] != tag {
        return Err(Error::ParseError);
    }
    Ok(&content[tag.len()..])
}

fn parse_u32(content: &[u8]) -> Result<(&[u8], u32)> {
    if content.len() < 4 {
        return Err(Error::ParseError);
    }
    let value = u32::from_be_bytes(<[u8; 4]>::try_from(&content[..4]).unwrap());
    Ok((&content[4..], value))
}

fn parse_bytes(content: &[u8]) -> Result<(&[u8], &[u8])> {
    let (content, len) = parse_u32(content)?;
    if content.len() < len as usize {
        return Err(Error::ParseError);
    }
    Ok((&content[len as usize..], &content[..len as usize]))
}
