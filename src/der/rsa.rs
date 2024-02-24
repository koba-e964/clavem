use asn1_rs::{DerSequence, FromDer, Integer};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::int::{DisplayedInt, PrivateInt};
use crate::span::Span;

#[derive(Serialize)]
pub struct PublicKey {
    pub modulus: DisplayedInt,
    pub exponent: DisplayedInt,
}

#[derive(Serialize)]
pub struct OtherPrime {
    pub prime: PrivateInt,
    pub exponent: PrivateInt,
    pub coefficient: PrivateInt,
}

#[derive(Serialize)]
pub struct PrivateKey {
    pub modulus: DisplayedInt,
    #[serde(rename = "publicExponent")]
    pub public_exponent: DisplayedInt,
    #[serde(rename = "privateExponent")]
    pub private_exponent: PrivateInt,
    pub prime1: PrivateInt,
    pub prime2: PrivateInt,
    pub exponent1: PrivateInt,
    pub exponent2: PrivateInt,
    pub coefficient: PrivateInt,
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "otherPrimeInfos")]
    pub other_primes: Vec<OtherPrime>,
}

#[allow(non_snake_case)]
pub mod privkey {
    use asn1_rs::{Any, SequenceOf};

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
        publicExponent: Integer<'a>,
        privateExponent: Integer<'a>,
        prime1: Integer<'a>,
        prime2: Integer<'a>,
        exponent1: Integer<'a>,
        exponent2: Integer<'a>,
        coefficient: Integer<'a>,
        otherPrimeInfos: Option<Any<'a>>, // OPTIONAL
    }

    pub fn parse(content: &[u8]) -> Result<PrivateKey> {
        let (_rem, value) = RsaPrivateKeyAsn1::from_der(content).map_err(asn1_rs::Error::from)?;
        let other_primes = if value.version.as_i32() == Ok(0) {
            if value.otherPrimeInfos.is_some() {
                return Err(Error::InvalidInputError);
            }
            Vec::new()
        } else {
            let other_primes = if let Some(info) = value.otherPrimeInfos {
                info
            } else {
                return Err(Error::InvalidInputError);
            };
            let other_primes = SequenceOf::<OtherPrimeInfoAsn1>::try_from(other_primes)?;
            other_primes
                .into_iter()
                .map(|info| OtherPrime {
                    prime: (&info.prime).into(),
                    exponent: (&info.exponent).into(),
                    coefficient: (&info.coefficient).into(),
                })
                .collect()
        };
        Ok(PrivateKey {
            modulus: DisplayedInt::new(value.modulus.as_bigint(), Span::new(0, 0)), // TODO: span
            public_exponent: DisplayedInt::new(value.publicExponent.as_bigint(), Span::new(0, 0)), // TODO: span
            private_exponent: value.privateExponent.into(),
            prime1: value.prime1.into(),
            prime2: value.prime2.into(),
            exponent1: value.exponent1.into(),
            exponent2: value.exponent2.into(),
            coefficient: value.coefficient.into(),
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

    pub fn parse(content: &[u8]) -> Result<PublicKey> {
        let (_, key) = RsaPublicKeyAsn1::from_der(content).unwrap();
        Ok(PublicKey {
            modulus: DisplayedInt::new(key.modulus.as_bigint(), Span::new(0, 0)), // TODO: span
            exponent: DisplayedInt::new(key.exponent.as_bigint(), Span::new(0, 0)), // TODO: span
        })
    }
}
