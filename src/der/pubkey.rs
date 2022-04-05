#![allow(non_snake_case)]
use asn1_rs::{Any, BitString, DerSequence, FromDer, Oid};
use oid_registry::OidRegistry;
use serde::Serialize;

use crate::der::object::Object;
use crate::der::{ed, rsa};
use crate::error::Result;

// RFC 2459
// https://datatracker.ietf.org/doc/html/rfc2459#section-4.1.1.2
#[derive(DerSequence, Debug)]
pub(crate) struct AlgorithmIdentifierAsn1<'a> {
    pub(crate) algorithm: Oid<'a>,
    #[allow(unused)] // we haven't seen algorithms that use parameter
    parameter: Option<Any<'a>>,
}

impl<'a> AlgorithmIdentifierAsn1<'a> {
    pub(crate) fn to(&self, registry: &OidRegistry) -> Object {
        let algo = &self.algorithm;
        (algo, registry.get(algo)).into()
    }
}

// RFC 2459
// https://datatracker.ietf.org/doc/html/rfc2459#section-4.1
#[derive(DerSequence, Debug)]
pub(crate) struct SubjectPublicKeyInfoAsn1<'a> {
    algorithm: AlgorithmIdentifierAsn1<'a>,
    pub(crate) subjectPublicKey: BitString<'a>,
}

impl<'a> SubjectPublicKeyInfoAsn1<'a> {
    pub(crate) fn to(&self, registry: &OidRegistry) -> Result<PublicKey> {
        let x25519 = Oid::from(&[1, 3, 101, 110]).unwrap();
        let x448 = Oid::from(&[1, 3, 101, 111]).unwrap();
        let value = self;
        let algorithm = &value.algorithm.algorithm;
        let mut wrapped = PublicKey {
            algorithm: value.algorithm.to(registry),
            public_key: serde_json::Value::String("unknown algorithm".to_string()),
        };
        if *algorithm == oid_registry::OID_PKCS1_RSAENCRYPTION
            || *algorithm == oid_registry::OID_PKCS1_RSASSAPSS
        {
            let key = rsa::pubkey::parse(&value.subjectPublicKey.data)?;
            wrapped.public_key = serde_json::to_value(&key)?;
        }
        if *algorithm == oid_registry::OID_SIG_ED25519
            || *algorithm == oid_registry::OID_SIG_ED448
            || *algorithm == x25519
            || *algorithm == x448
        {
            let key = ed::pubkey::parse(&value.subjectPublicKey.data)?;
            wrapped.public_key = serde_json::to_value(&key)?;
        }
        Ok(wrapped)
    }
}

#[derive(Serialize)]
pub struct PublicKey {
    pub algorithm: Object,
    pub public_key: serde_json::Value,
}

pub fn parse_public_key(content: &[u8]) -> Result<PublicKey> {
    let registry = OidRegistry::default().with_crypto().with_kdf().with_x509();
    let (_rem, value) = SubjectPublicKeyInfoAsn1::from_der(content).unwrap();
    value.to(&registry)
}
