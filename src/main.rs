use serde::Serialize;
use std::{env, fs};

use clavem::privkey::{parse_private_key, PrivateKey};
use clavem::pubkey::{parse_public_key, PublicKey};
use clavem::{cert, csr, openssh, rsa};

fn parse_as_pem(data: &[u8]) -> pem::Result<()> {
    let result = pem::parse_many(&data)?;
    for pem in result {
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
        if pem.tag == "OPENSSH PRIVATE KEY" {
            let value = openssh::privkey::parse(&pem.contents).unwrap();
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

fn main() -> Result<(), ()> {
    let args: Vec<String> = env::args().into_iter().collect();
    let filename = args[1].clone();
    let data = fs::read(filename).expect("Unable to read file");
    if parse_as_pem(&data).is_ok() {
        return Ok(());
    }
    eprintln!("Unsupported!");
    Err(())
}
