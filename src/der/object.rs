use oid_registry::{Oid, OidEntry};
use serde::Serialize;

/// Representation of an OID entry.
pub struct Object {
    pub oid: String,
    pub sn: Option<String>,
    pub description: Option<String>,
}

impl Serialize for Object {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if let Some(sn) = &self.sn {
            serializer.serialize_str(&format!("{} ({})", sn, self.oid))
        } else {
            serializer.serialize_str(&format!("unknown ({})", self.oid))
        }
    }
}

impl<'a> From<(&'a Oid<'a>, Option<&'a OidEntry>)> for Object {
    fn from((oid, entry): (&Oid, Option<&OidEntry>)) -> Self {
        Object {
            oid: oid.to_id_string(),
            sn: entry.map(|entry| entry.sn().to_owned()),
            description: entry.map(|entry| entry.description().to_owned()),
        }
    }
}
