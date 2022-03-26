use asn1_rs::{DerSequence, FromDer, Integer};
use serde::Serialize;

use crate::error::Result;
use crate::int::DisplayedInt;

#[derive(Serialize)]
pub struct RsaPublicKey {
    pub modulus: DisplayedInt,
    pub exponent: DisplayedInt,
}

#[derive(Serialize)]
pub struct RsaPrivateKey {
    pub modulus: DisplayedInt,
    pub public_exponent: DisplayedInt,
    pub private_exponent: DisplayedInt,
    pub prime1: DisplayedInt,
    pub prime2: DisplayedInt,
    pub exponent1: DisplayedInt,
    pub exponent2: DisplayedInt,
    pub coefficient: DisplayedInt,
    pub other_primes: Vec<DisplayedInt>,
}

#[allow(non_snake_case)]
pub mod privkey {
    use super::*;

    // RFC 8017
    // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2
    #[derive(DerSequence, Debug)]
    #[allow(unused)]
    struct OtherPrimeInfoAsn1<'a> {
        prime: Integer<'a>,
        exponent: Integer<'a>,
        coefficient: Integer<'a>,
    }

    #[derive(DerSequence)]
    struct RsaPrivateKeyAsn1<'a> {
        version: Integer<'a>,
        modulus: Integer<'a>,
        #[allow(non_snake_case)] // reason: Names are taken from the RFC
        publicExponent: Integer<'a>,
        #[allow(non_snake_case)] // reason: Names are taken from the RFC
        privateExponent: Integer<'a>,
        prime1: Integer<'a>,
        prime2: Integer<'a>,
        exponent1: Integer<'a>,
        exponent2: Integer<'a>,
        coefficient: Integer<'a>,
        // otherPrimeInfos: Sequence<'a>, // OPTIONAL
    }

    pub fn parse(content: &[u8]) -> Result<RsaPrivateKey> {
        let (_rem, value) = RsaPrivateKeyAsn1::from_der(content).unwrap();
        let other_primes = if value.version.as_i32() == Ok(0) {
            Vec::new()
        } else {
            todo!()
        };
        Ok(RsaPrivateKey {
            modulus: value.modulus.as_bigint().into(),
            public_exponent: value.publicExponent.as_bigint().into(),
            private_exponent: value.privateExponent.as_bigint().into(),
            prime1: value.prime1.as_bigint().into(),
            prime2: value.prime2.as_bigint().into(),
            exponent1: value.exponent1.as_bigint().into(),
            exponent2: value.exponent2.as_bigint().into(),
            coefficient: value.coefficient.as_bigint().into(),
            other_primes,
        })
    }
}

pub mod pubkey {
    use super::*;

    // RFC 8017
    // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1
    #[derive(DerSequence, Debug)]
    struct RsaPublicKeyAsn1<'a> {
        modulus: Integer<'a>,
        exponent: Integer<'a>,
    }

    pub fn parse(content: &[u8]) -> Result<RsaPublicKey> {
        let (_, key) = RsaPublicKeyAsn1::from_der(content).unwrap();
        Ok(RsaPublicKey {
            modulus: key.modulus.as_bigint().into(),
            exponent: key.exponent.as_bigint().into(),
        })
    }
}
