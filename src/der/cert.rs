#![allow(non_snake_case)]

use asn1_rs::{
    Any, BitString, DerSequence, FromDer, Integer, OptTaggedExplicit, Sequence, TaggedExplicit,
};
use oid_registry::OidRegistry;
use serde::Serialize;

use crate::der::object::Object;
use crate::der::pubkey::{AlgorithmIdentifierAsn1, PublicKey, SubjectPublicKeyInfoAsn1};
use crate::der::registry;
use crate::error::{Error, Result};
use crate::int::DisplayedInt;
use crate::string::BitStr;

#[derive(DerSequence)]
struct TBSCertificateAsn1<'a> {
    version: TaggedExplicit<Integer<'a>, 0>,
    serialNumber: Integer<'a>,
    signature: AlgorithmIdentifierAsn1<'a>,
    #[allow(unused)]
    issuer: Sequence<'a>,
    #[allow(unused)]
    validity: Any<'a>,
    #[allow(unused)]
    subject: Sequence<'a>,
    subjectPublicKeyInfo: SubjectPublicKeyInfoAsn1<'a>,
    // issuerUniqueID: OptTaggedImplicit<BitString<'a>, 1>,
    // subjectUniqueID: Option<Any<'a>>, //TaggedValue<BitString<'a>, Implicit, 0b10 /* ContextSpecific */, 2>,
    #[allow(unused)]
    extensions: OptTaggedExplicit<Any<'a>, 3>,
}

#[derive(Serialize)]
pub struct TBSCertificate {
    pub version: DisplayedInt,
    #[serde(rename = "serialNumber")]
    pub serial_number: DisplayedInt,
    pub signature: Object,
    issuer: (),
    validity: (),
    subject: (),
    #[serde(rename = "subjectPublicKeyInfo")]
    pub subject_pki: PublicKey,
    issuer_uid: (),
}

impl TBSCertificate {
    fn try_from(value: TBSCertificateAsn1, registry: &OidRegistry) -> Result<Self> {
        eprintln!("{:?}", value.extensions);
        Ok(TBSCertificate {
            version: value.version.into_inner().into(),
            serial_number: value.serialNumber.into(),
            signature: value.signature.to(registry),
            issuer: (),
            validity: (),
            subject: (),
            subject_pki: value.subjectPublicKeyInfo.to(registry)?,
            issuer_uid: (),
        })
    }
}

#[derive(DerSequence)]
struct CertificateAsn1<'a> {
    tbsCertificate: TBSCertificateAsn1<'a>,
    signatureAlgorithm: AlgorithmIdentifierAsn1<'a>,
    signatureValue: BitString<'a>,
}

#[derive(Serialize)]
pub struct Certificate {
    #[serde(rename = "tbsCertificate")]
    pub tbs_certificate: TBSCertificate,
    #[serde(rename = "signatureAlgorithm")]
    pub signature_algorithm: Object,
    #[serde(rename = "signatureValue")]
    pub signature_value: BitStr,
}

impl Certificate {
    fn try_from(value: CertificateAsn1, registry: &OidRegistry) -> Result<Self> {
        Ok(Self {
            tbs_certificate: TBSCertificate::try_from(value.tbsCertificate, registry)?,
            signature_algorithm: value.signatureAlgorithm.to(registry),
            signature_value: value.signatureValue.into(),
        })
    }
}

pub fn parse(content: &[u8]) -> Result<Certificate> {
    let registry = registry::get();
    let (content, value) = CertificateAsn1::from_der(content).map_err(asn1_rs::Error::from)?;
    if !content.is_empty() {
        return Err(Error::ParseError);
    }
    Certificate::try_from(value, &registry)
}
