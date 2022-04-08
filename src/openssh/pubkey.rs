use serde::Serialize;

use super::error::{Error, Result};

#[derive(Serialize)]
pub struct PubPart {
    pub algo: String,
    pub content: serde_json::Value,
}

#[derive(Serialize)]
pub struct PublicKey<'a> {
    pub data: PubPart,
    pub comment: Option<&'a str>,
}

pub fn parse_data(content: &[u8]) -> Result<(&[u8], PubPart)> {
    let (mut content, algo) = super::parse_bytes(content)?;
    let algo = String::from_utf8(algo.to_vec())?;
    let mut wrapped = PubPart {
        algo: algo.clone(),
        content: serde_json::Value::Null,
    };
    let mut parsed = false;
    if algo == "ecdsa-sha2-nistp256" {
        let (remaining, pub_key) = super::ecdsa::pubkey::parse(content)?;
        content = remaining;
        wrapped.content = serde_json::to_value(&pub_key)?;
        parsed = true;
    }
    if algo == "ssh-dss" {
        let (remaining, pub_key) = super::dsa::pubkey::parse(content)?;
        content = remaining;
        wrapped.content = serde_json::to_value(&pub_key)?;
        parsed = true;
    }
    if algo == "ssh-ed25519" {
        let (remaining, pub_key) = super::ed25519::pubkey::parse(content)?;
        content = remaining;
        wrapped.content = serde_json::to_value(&pub_key)?;
        parsed = true;
    }
    if algo == "ssh-rsa" {
        let (remaining, pub_key) = super::rsa::pubkey::parse(content)?;
        content = remaining;
        wrapped.content = serde_json::to_value(&pub_key)?;
        parsed = true;
    }
    if !parsed {
        return Err(Error::ParseError);
    }
    Ok((content, wrapped))
}

/// Parse a string in AUTHORIZED_KEYS FILE FORMAT as in [sshd's manual](https://man.openbsd.org/OpenBSD-7.0/sshd#AUTHORIZED_KEYS_FILE_FORMAT).
///
/// `key` must be a single line: it must contain a newline at the end, and must not contain any other newlines.
pub fn parse(key: &str) -> Result<PublicKey> {
    // TODO: support options

    let stripped = if let Some(s) = key.strip_suffix("\r\n") {
        s
    } else if let Some(s) = key.strip_suffix('\n') {
        s
    } else if let Some(s) = key.strip_suffix('\r') {
        s
    } else {
        return Err(Error::ParseError);
    };
    let s: Vec<_> = stripped.split(' ').collect();
    if s.len() != 2 && s.len() != 3 {
        return Err(Error::ParseError);
    }
    let algo = s[0];
    let data = s[1];
    let comment = s.get(2).copied();
    let data = base64::decode(data)?;
    let (remaining, data) = parse_data(&data)?;
    if !remaining.is_empty() || data.algo != algo {
        return Err(Error::ParseError);
    }
    Ok(PublicKey { data, comment })
}

#[cfg(test)]
mod tests {
    mod ed25519 {
        use super::super::*;
        #[test]
        fn parse_test_positive() {
            let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF/cpeiuO8aMA4abrDs87slcIRMK/AhG3WNVKg7X48Aj test\n";
            let result = parse(key);
            assert!(result.is_ok());
            let result = result.unwrap();
            assert_eq!(result.data.algo, "ssh-ed25519");
            assert_eq!(result.comment, Some("test"));
        }
    }

    mod rsa {
        use super::super::*;
        #[test]
        fn parse_test_negative() {
            // algo mismatch (ssh-rsa != ssh-ed25519)
            let key =
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIF/cpeiuO8aMA4abrDs87slcIRMK/AhG3WNVKg7X48Aj test\n";
            let result = parse(key);
            assert!(matches!(result, Err(Error::ParseError)));
        }
    }

    mod general {
        use super::super::*;
        #[test]
        fn parse_test_positive() {
            // Comment is missing, but it's ok
            let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF/cpeiuO8aMA4abrDs87slcIRMK/AhG3WNVKg7X48Aj\n";
            let result = parse(key);
            assert!(result.is_ok());
            let result = result.unwrap();
            assert_eq!(result.data.algo, "ssh-ed25519");
            assert_eq!(result.comment, None);
        }

        #[test]
        fn parse_test_negative_0() {
            // No newline
            let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF/cpeiuO8aMA4abrDs87slcIRMK/AhG3WNVKg7X48Aj test";
            let result = parse(key);
            assert!(matches!(result, Err(Error::ParseError)));
        }
        #[test]
        fn parse_test_negative_1() {
            // Algorithm missing
            let key = "AAAAC3NzaC1lZDI1NTE5AAAAIF/cpeiuO8aMA4abrDs87slcIRMK/AhG3WNVKg7X48Aj test";
            let result = parse(key);
            assert!(matches!(result, Err(Error::ParseError)));
        }
    }
}
