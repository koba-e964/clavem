use oid_registry::{Oid, OidEntry};
use serde_lite::{Intermediate, Serialize};

/// Representation of an OID entry.
pub struct Object {
    pub oid: String,
    pub sn: Option<String>,
    pub description: Option<String>,
}

impl Serialize for Object {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::String(if let Some(sn) = &self.sn {
            format!("{} ({})", sn, self.oid)
        } else {
            format!("unknown ({})", self.oid)
        }))
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
