use serde::Serialize;

use crate::string::BitStr;

#[derive(Serialize)]
pub struct PublicKeyCertificate {
    pub nonce: BitStr,
    pub inner: serde_json::Value,
    pub serial: u64,
    #[serde(rename = "type")]
    pub type_: u32,
    pub key_id: BitStr,
    pub valid_principals: BitStr,
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical_options: BitStr,
    pub extensions: BitStr,
    pub reserved: BitStr,
    pub signature_key: BitStr,
    pub signature: BitStr,
}
