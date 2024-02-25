use base64::Engine;
use serde::Serialize;

use crate::{span::Span, string::BitStr};

use super::{
    cert::PublicKeyCertificate,
    error::{Error, Result},
};

#[derive(Serialize)]
pub struct PubPart {
    pub algo: String,
    pub content: serde_json::Value,
    pub span: Span,
}

#[derive(Serialize)]
pub struct PublicKey<'a> {
    pub data: PubPart,
    pub comment: Option<&'a str>,
}

pub fn parse_data(content: &[u8], offset: usize) -> Result<(&[u8], Span, PubPart)> {
    let (mut content, algo_span, algo) = super::parse_bytes(content, offset)?;
    let algo = String::from_utf8(algo.to_vec())?;
    let mut wrapped = PubPart {
        algo: algo.clone(),
        content: serde_json::Value::Null,
        span: Span::new(offset, content.len() + offset),
    };
    let mut parsed = false;
    let mut key_span_end = 0;
    if algo == "ecdsa-sha2-nistp256" {
        let (remaining, pub_key_span, pub_key) =
            super::ecdsa::pubkey::parse(content, algo_span.end)?;
        content = remaining;
        wrapped.content = serde_json::to_value(pub_key)?;
        parsed = true;
        key_span_end = pub_key_span.end;
    }
    if algo == "ssh-dss" {
        let (remaining, pub_key_span, pub_key) = super::dsa::pubkey::parse(content, algo_span.end)?;
        content = remaining;
        wrapped.content = serde_json::to_value(pub_key)?;
        parsed = true;
        key_span_end = pub_key_span.end;
    }
    if algo == "ssh-ed25519" {
        let (remaining, pub_key_span, pub_key) =
            super::ed25519::pubkey::parse(content, algo_span.end)?;
        content = remaining;
        wrapped.content = serde_json::to_value(pub_key)?;
        parsed = true;
        key_span_end = pub_key_span.end;
    }
    if algo == "ssh-rsa" {
        let (remaining, pub_key_span, pub_key) = super::rsa::pubkey::parse(content, algo_span.end)?;
        content = remaining;
        wrapped.content = serde_json::to_value(pub_key)?;
        parsed = true;
        key_span_end = pub_key_span.end;
    }
    if let Some(algo_inner) = algo.strip_suffix("-cert-v01@openssh.com") {
        // Certificates
        // Format: https://github.com/openssh/openssh-portable/blob/V_9_1_P1/PROTOCOL.certkeys
        parsed = true;
        let (mut remaining, nonce_span, nonce) = super::parse_bytes(content, algo_span.end)?;
        let mut wrapped2 = PubPart {
            algo: algo.clone(),
            content: serde_json::Value::Null,
            span: Span::new(offset, content.len() + offset),
        };
        let mut parsed = false;
        let mut key_span_end2 = 0;
        if algo_inner == "ecdsa-sha2-nistp256" {
            let (content, pub_key_span, pub_key) =
                super::ecdsa::pubkey::parse(remaining, nonce_span.end)?;
            remaining = content;
            wrapped2.content = serde_json::to_value(pub_key)?;
            parsed = true;
            key_span_end2 = pub_key_span.end;
        }
        if algo_inner == "ssh-dss" {
            let (content, pub_key_span, pub_key) =
                super::dsa::pubkey::parse(remaining, nonce_span.end)?;
            remaining = content;
            wrapped2.content = serde_json::to_value(pub_key)?;
            parsed = true;
            key_span_end2 = pub_key_span.end;
        }
        if algo_inner == "ssh-ed25519" {
            let (content, pub_key_span, pub_key) =
                super::ed25519::pubkey::parse(remaining, nonce_span.end)?;
            remaining = content;
            wrapped2.content = serde_json::to_value(pub_key)?;
            parsed = true;
            key_span_end2 = pub_key_span.end;
        }
        if algo_inner == "ssh-rsa" {
            let (content, pub_key_span, pub_key) =
                super::rsa::pubkey::parse(remaining, nonce_span.end)?;
            remaining = content;
            wrapped2.content = serde_json::to_value(pub_key)?;
            parsed = true;
            key_span_end2 = pub_key_span.end;
        }
        if !parsed {
            return Err(Error::ParseError);
        }
        wrapped2.span = Span::new(nonce_span.end, key_span_end2);
        let (remaining, serial_span, serial) = super::parse_u64(remaining, key_span_end2)?;
        let (remaining, type_span, type_) = super::parse_u32(remaining, serial_span.end)?;
        let (remaining, key_id_span, key_id) = super::parse_bytes(remaining, type_span.end)?;
        let (remaining, valid_principals_span, valid_principals) =
            super::parse_bytes(remaining, key_id_span.end)?;
        let (remaining, valid_after_span, valid_after) =
            super::parse_u64(remaining, valid_principals_span.end)?;
        let (remaining, valid_before_span, valid_before) =
            super::parse_u64(remaining, valid_after_span.end)?;
        let (remaining, critical_options_span, critical_options) =
            super::parse_bytes(remaining, valid_before_span.end)?;
        let (remaining, extensions_span, extensions) =
            super::parse_bytes(remaining, critical_options_span.end)?;
        let (remaining, reserved_span, reserved) =
            super::parse_bytes(remaining, extensions_span.end)?;
        let (remaining, signature_key_span, signature_key) =
            super::parse_bytes(remaining, reserved_span.end)?;
        let (remaining, signature_span, signature) =
            super::parse_bytes(remaining, signature_key_span.end)?;
        let pubkey_certificate = PublicKeyCertificate {
            nonce: BitStr::from(nonce),
            inner: serde_json::to_value(&wrapped2)?,
            serial,
            type_,
            key_id: BitStr::from(key_id),
            valid_principals: BitStr::from(valid_principals),
            valid_after,
            valid_before,
            critical_options: BitStr::from(critical_options),
            extensions: BitStr::from(extensions),
            reserved: BitStr::from(reserved),
            signature_key: BitStr::from(signature_key),
            signature: BitStr::from(signature),
        };
        content = remaining;
        wrapped.span = Span::new(offset, signature_span.end);
        wrapped.content = serde_json::to_value(&pubkey_certificate)?;
        key_span_end = signature_span.end;
    }
    if !parsed {
        return Err(Error::ParseError);
    }
    wrapped.span = Span::new(offset, key_span_end);
    Ok((content, wrapped.span, wrapped))
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
    let data = base64::prelude::BASE64_STANDARD.decode(data)?;
    let (remaining, _span, data) = parse_data(&data, 0)?;
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
