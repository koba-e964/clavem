use serde::Serialize;
use std::{env, fs};

#[cfg(feature = "der")]
use clavem::der::privkey::{parse_private_key, PrivateKey};
#[cfg(feature = "der")]
use clavem::der::pubkey::{parse_public_key, PublicKey};
#[cfg(feature = "der")]
use clavem::der::{cert, csr, rsa};
#[cfg(feature = "openssh")]
use clavem::openssh;

fn parse_as_pem(data: &[u8]) -> pem::Result<()> {
    let result = pem::parse_many(&data)?;
    if result.is_empty() {
        return Err(pem::PemError::MissingData);
    }
    for pem in result {
        #[cfg(feature = "der")]
        if pem.tag == "PUBLIC KEY" {
            let value = parse_public_key(&pem.contents).unwrap();
            #[derive(Serialize)]
            struct Wrapping {
                #[serde(rename = "type")]
                ty: &'static str,
                value: PublicKey,
            }
            let wrapped = Wrapping {
                ty: "PEM public key",
                value,
            };
            println!("{}", serde_json::to_string_pretty(&wrapped).unwrap());
        }
        #[cfg(feature = "der")]
        if pem.tag == "RSA PRIVATE KEY" {
            let value = rsa::privkey::parse(&pem.contents).unwrap();
            #[derive(Serialize)]
            struct Wrapping {
                #[serde(rename = "type")]
                ty: &'static str,
                value: rsa::PrivateKey,
            }
            let wrapped = Wrapping {
                ty: "PEM RSA private key",
                value,
            };
            println!("{}", serde_json::to_string_pretty(&wrapped).unwrap());
        }
        #[cfg(feature = "der")]
        if pem.tag == "PRIVATE KEY" {
            let value = parse_private_key(&pem.contents).unwrap();
            #[derive(Serialize)]
            struct Wrapping {
                #[serde(rename = "type")]
                ty: &'static str,
                value: PrivateKey,
            }
            let wrapped = Wrapping {
                ty: "PEM private key",
                value,
            };
            println!("{}", serde_json::to_string_pretty(&wrapped).unwrap());
        }
        #[cfg(feature = "der")]
        if pem.tag == "CERTIFICATE" {
            let value = cert::parse(&pem.contents).unwrap();
            #[derive(Serialize)]
            struct Wrapping {
                #[serde(rename = "type")]
                ty: &'static str,
                value: cert::Certificate,
            }
            let wrapped = Wrapping {
                ty: "PEM certificate",
                value,
            };
            println!("{}", serde_json::to_string_pretty(&wrapped).unwrap());
        }
        #[cfg(feature = "der")]
        if pem.tag == "CERTIFICATE REQUEST" {
            let value = csr::parse_csr(&pem.contents).unwrap();
            #[derive(Serialize)]
            struct Wrapping {
                #[serde(rename = "type")]
                ty: &'static str,
                value: csr::CertificationRequest,
            }
            let wrapped = Wrapping {
                ty: "PEM certificate request",
                value,
            };
            println!("{}", serde_json::to_string_pretty(&wrapped).unwrap());
        }
        #[cfg(feature = "openssh")]
        if pem.tag == "OPENSSH PRIVATE KEY" {
            let value = openssh::privkey::parse(&pem.contents, 0).unwrap();
            #[derive(Serialize)]
            struct Wrapping {
                #[serde(rename = "type")]
                ty: &'static str,
                value: openssh::privkey::PrivateKey,
            }
            let wrapped = Wrapping {
                ty: "OPENSSH private key",
                value,
            };
            println!("{}", serde_json::to_string_pretty(&wrapped).unwrap());
        }
    }
    Ok(())
}

fn main() -> Result<(), &'static str> {
    let args: Vec<String> = env::args().into_iter().collect();
    let filename = args[1].clone();
    let data = fs::read(filename).expect("Unable to read file");
    if let Ok(data) = std::str::from_utf8(&data) {
        if let Ok(value) = openssh::pubkey::parse(data) {
            #[derive(Serialize)]
            struct Wrapping<'a> {
                #[serde(rename = "type")]
                ty: &'static str,
                value: openssh::pubkey::PublicKey<'a>,
            }
            let wrapped = Wrapping {
                ty: "OPENSSH public key",
                value,
            };
            println!("{}", serde_json::to_string_pretty(&wrapped).unwrap());

            return Ok(());
        }
    }
    if parse_as_pem(&data).is_ok() {
        return Ok(());
    }
    Err("Unsupported!")
}
