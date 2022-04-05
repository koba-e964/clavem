#![allow(non_snake_case)]
use asn1_rs::{Any, DerSequence, FromDer, Integer, OctetString, Oid};
use serde::Serialize;

use crate::der::object::Object;
use crate::der::pubkey::AlgorithmIdentifierAsn1;
use crate::der::{ed, registry, rsa};
use crate::error::{Error, Result};

// RFC 5208
// https://datatracker.ietf.org/doc/html/rfc5208#section-5
#[derive(DerSequence, Debug)]
struct PrivateKeyInfoAsn1<'a> {
    version: Integer<'a>,
    privateKeyAlgorithm: AlgorithmIdentifierAsn1<'a>,
    privateKey: OctetString<'a>,
    #[allow(unused)]
    attributes: Option<Any<'a>>,
}

#[derive(Serialize)]
pub struct PrivateKey {
    pub algorithm: Object,
    pub private_key: serde_json::Value,
}

pub fn parse_private_key(content: &[u8]) -> Result<PrivateKey> {
    let registry = registry::get();
    let x25519 = Oid::from(&[1, 3, 101, 110]).unwrap();
    let x448 = Oid::from(&[1, 3, 101, 111]).unwrap();
    let (content, key) = PrivateKeyInfoAsn1::from_der(content).unwrap();
    if !content.is_empty() {
        return Err(Error::ParseError);
    }
    if key.version.as_i32() != Ok(0) {
        return Err(Error::InvalidInputError);
    }
    let algorithm = &key.privateKeyAlgorithm.algorithm;
    let mut wrapped = PrivateKey {
        algorithm: (algorithm, registry.get(algorithm)).into(),
        private_key: serde_json::Value::String("unknown algorithm".to_string()),
    };
    if *algorithm == oid_registry::OID_PKCS1_RSAENCRYPTION
        || *algorithm == oid_registry::OID_PKCS1_RSASSAPSS
    {
        let key = rsa::privkey::parse(key.privateKey.as_cow())?;
        wrapped.private_key = serde_json::to_value(&key)?;
    }
    if *algorithm == oid_registry::OID_SIG_ED25519
        || *algorithm == oid_registry::OID_SIG_ED448
        || *algorithm == x25519
        || *algorithm == x448
    {
        let key = ed::privkey::parse(key.privateKey.as_cow())?;
        wrapped.private_key = serde_json::to_value(&key)?;
    }
    Ok(wrapped)
}
