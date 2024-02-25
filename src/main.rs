use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::fs;

#[cfg(feature = "der")]
use clavem::der::privkey::{parse_private_key, PrivateKey};
#[cfg(feature = "der")]
use clavem::der::pubkey::{parse_public_key, PublicKey};
#[cfg(feature = "der")]
use clavem::der::{cert, csr, rsa};
#[cfg(feature = "openssh")]
use clavem::openssh;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long = "display-span")]
    display_span: bool,
    #[arg(
        long = "output-format",
        default_value_t = OutputFormat::Text,
        value_enum,
    )]
    output_format: OutputFormat, // TODO: add support for Text
    #[arg(long)]
    all: bool,
    filename: String,
}

fn remove_spans(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("span");
            for (_, value) in map {
                remove_spans(value);
            }
        }
        serde_json::Value::Array(array) => {
            for value in array {
                remove_spans(value);
            }
        }
        _ => {}
    }
}

fn display<T: Serialize>(args: &Args, wrapped: &T) {
    let mut json_value = serde_json::to_value(wrapped).unwrap();
    if !args.display_span {
        // remove all spans
        remove_spans(&mut json_value);
    }
    println!("{}", serde_json::to_string_pretty(&json_value).unwrap());
}

fn parse_as_pem(args: &Args, data: &[u8]) -> pem::Result<()> {
    let result = pem::parse_many(data)?;
    if result.is_empty() {
        return Err(pem::PemError::MissingData);
    }
    for pem in result {
        #[cfg(feature = "der")]
        if pem.tag() == "PUBLIC KEY" {
            let value = parse_public_key(pem.contents()).unwrap();
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
            display(args, &wrapped);
        }
        #[cfg(feature = "der")]
        if pem.tag() == "RSA PRIVATE KEY" {
            let value = rsa::privkey::parse(pem.contents()).unwrap();
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
            display(args, &wrapped);
        }
        #[cfg(feature = "der")]
        if pem.tag() == "PRIVATE KEY" {
            let value = parse_private_key(pem.contents()).unwrap();
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
            display(args, &wrapped);
        }
        #[cfg(feature = "der")]
        if pem.tag() == "CERTIFICATE" {
            let value = cert::parse(pem.contents()).unwrap();
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
        if pem.tag() == "CERTIFICATE REQUEST" {
            let value = csr::parse_csr(pem.contents()).unwrap();
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
            display(args, &wrapped);
        }
        #[cfg(feature = "openssh")]
        if pem.tag() == "OPENSSH PRIVATE KEY" {
            let value = openssh::privkey::parse(pem.contents(), 0).unwrap();
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
            display(args, &wrapped);
        }
    }
    Ok(())
}

fn main() -> Result<(), &'static str> {
    let mut args: Args = Args::parse();
    let filename = args.filename.clone();
    if args.all {
        args.display_span = true;
    }
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
            display(&args, &wrapped);

            return Ok(());
        }
    }
    if parse_as_pem(&args, &data).is_ok() {
        return Ok(());
    }
    Err("Unsupported!")
}
