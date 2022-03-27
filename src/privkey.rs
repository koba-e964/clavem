#![allow(non_snake_case)]
use asn1_rs::{Any, DerSequence, FromDer, Integer, OctetString, Oid};
use oid_registry::OidRegistry;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::object::Object;
use crate::pubkey::AlgorithmIdentifierAsn1;
use crate::{ed, rsa};

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
    let registry = OidRegistry::default().with_crypto().with_kdf().with_x509();
    let x25519 = Oid::from(&[1, 3, 101, 110]).unwrap();
    let x448 = Oid::from(&[1, 3, 101, 111]).unwrap();
    let (_, key) = PrivateKeyInfoAsn1::from_der(content).unwrap();
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
