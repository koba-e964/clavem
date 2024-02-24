#![allow(non_snake_case)]
use asn1_rs::{Any, BitString, DerSequence, FromDer, Integer, Oid, Sequence, Set};
use oid_registry::OidRegistry;
use serde::Serialize;

use crate::der::object::Object;
use crate::der::pubkey::{AlgorithmIdentifierAsn1, PublicKey, SubjectPublicKeyInfoAsn1};
use crate::der::registry;
use crate::error::{Error, Result};
use crate::int::DisplayedInt;
use crate::span::Span;
use crate::string::BitStr;

// https://www.itu.int/ITU-T/formal-language/itu-t/x/x501/2012/InformationFramework.html#InformationFramework.AttributeTypeAndValue
#[derive(DerSequence)]
#[allow(unused)]
struct AttributeTypeAndValueAsn1<'a> {
    r#type: Oid<'a>,
    value: Any<'a>,
}

#[derive(Serialize)]
pub struct AttributeTypeAndValue {
    #[serde(rename = "type")]
    pub ty: Object,
    pub value: (), // TODO
}

impl AttributeTypeAndValue {
    fn from(x: AttributeTypeAndValueAsn1, registry: &OidRegistry) -> Self {
        let entry = registry.get(&x.r#type);
        eprintln!("value = {:?}", x.value);
        Self {
            ty: (&x.r#type, entry).into(),
            value: (),
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc2986#section-4
#[derive(DerSequence)]
struct CertificationRequestInfoAsn1<'a> {
    version: Integer<'a>,
    subject: Sequence<'a>,
    subjectPKInfo: SubjectPublicKeyInfoAsn1<'a>,
    #[allow(unused)]
    attributes: Any<'a>,
}

#[derive(Serialize)]
pub struct CertificationRequestInfo {
    version: DisplayedInt,
    subject: Vec<Vec<AttributeTypeAndValue>>,
    #[serde(rename = "subjectPKInfo")]
    pub subject_pk_info: PublicKey,
}

impl CertificationRequestInfoAsn1<'_> {
    fn to(self, registry: &OidRegistry) -> Result<CertificationRequestInfo> {
        CertificationRequestInfo::from(self, registry)
    }
}
impl CertificationRequestInfo {
    fn from(value: CertificationRequestInfoAsn1, registry: &OidRegistry) -> Result<Self> {
        let subject: Vec<Vec<AttributeTypeAndValue>> = value
            .subject
            .der_iter()
            .map(|x| {
                let set: Set = x?;
                let val: Vec<_> = set
                    .der_iter()
                    .map(|x| Ok(AttributeTypeAndValue::from(x?, registry)))
                    .collect::<asn1_rs::Result<Vec<_>>>()?;
                Ok(val)
            })
            .collect::<asn1_rs::Result<Vec<_>>>()?;
        Ok(CertificationRequestInfo {
            version: DisplayedInt::new(value.version.as_bigint(), Span::new(0, 0)), // TODO span
            subject,
            subject_pk_info: value.subjectPKInfo.to(registry)?,
        })
    }
}
// https://datatracker.ietf.org/doc/html/rfc2986#section-4
#[derive(DerSequence)]
pub struct CertificationRequestAsn1<'a> {
    certificationRequestInfo: CertificationRequestInfoAsn1<'a>,
    signatureAlgorithm: AlgorithmIdentifierAsn1<'a>,
    signature: BitString<'a>,
}

#[derive(Serialize)]
pub struct CertificationRequest {
    #[serde(rename = "certificationRequestInfo")]
    pub certification_request_info: CertificationRequestInfo,
    #[serde(rename = "signatureAlgorithm")]
    pub signature_algorithm: Object,
    pub signature: BitStr,
}

impl<'a> CertificationRequestAsn1<'a> {
    fn to(self, registry: &OidRegistry) -> Result<CertificationRequest> {
        Ok(CertificationRequest {
            certification_request_info: self.certificationRequestInfo.to(registry)?,
            signature_algorithm: self.signatureAlgorithm.to(registry),
            signature: self.signature.clone().into(),
        })
    }
}

pub fn parse_csr(content: &[u8]) -> Result<CertificationRequest> {
    let registry = registry::get();
    let (content, value) =
        CertificationRequestAsn1::from_der(content).map_err(asn1_rs::Error::from)?;
    if !content.is_empty() {
        return Err(Error::ParseError);
    }
    eprintln!("{:?}", value.certificationRequestInfo.attributes);
    value.to(&registry)
}
