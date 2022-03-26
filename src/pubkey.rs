#![allow(non_snake_case)]
use asn1_rs::{Any, BitString, DerSequence, FromDer, Oid};
use oid_registry::OidRegistry;
use serde::Serialize;

use crate::error::Result;
use crate::object::Object;
use crate::{ed, rsa};

// RFC 2459
// https://datatracker.ietf.org/doc/html/rfc2459#section-4.1.1.2
#[derive(DerSequence, Debug)]
pub(crate) struct AlgorithmIdentifierAsn1<'a> {
    pub(crate) algorithm: Oid<'a>,
    #[allow(unused)] // we haven't seen algorithms that use parameter
    parameter: Option<Any<'a>>,
}

// RFC 2459
// https://datatracker.ietf.org/doc/html/rfc2459#section-4.1
#[derive(DerSequence, Debug)]
struct SubjectPublicKeyInfoAsn1<'a> {
    algorithm: AlgorithmIdentifierAsn1<'a>,
    subjectPublicKey: BitString<'a>,
}

#[derive(Serialize)]
pub struct PublicKey {
    pub algorithm: Object,
    pub public_key: serde_json::Value,
}

pub fn parse_public_key(content: &[u8]) -> Result<PublicKey> {
    let registry = OidRegistry::default().with_crypto().with_kdf().with_x509();
    let (_rem, value) = SubjectPublicKeyInfoAsn1::from_der(content).unwrap();
    let algorithm = &value.algorithm.algorithm;
    let mut wrapped = PublicKey {
        algorithm: (algorithm, registry.get(algorithm)).into(),
        public_key: serde_json::Value::String("unknown algorithm".to_string()),
    };
    if *algorithm == oid_registry::OID_PKCS1_RSAENCRYPTION
        || *algorithm == oid_registry::OID_PKCS1_RSASSAPSS
    {
        let key = rsa::pubkey::parse(&value.subjectPublicKey.data)?;
        wrapped.public_key = serde_json::to_value(&key)?;
    }
    if *algorithm == oid_registry::OID_SIG_ED25519 || *algorithm == oid_registry::OID_SIG_ED448 {
        let key = ed::pubkey::parse(&value.subjectPublicKey.data)?;
        wrapped.public_key = serde_json::to_value(&key)?;
    }
    Ok(wrapped)
}
