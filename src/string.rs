use asn1_rs::BitString;
use serde::Serialize;

pub struct BitStr {
    pub len: usize,
    pub unused: u8,
}

impl Serialize for BitStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.unused == 0 {
            serializer.serialize_str(&format!("(bitstring: {} bytes)", self.len))
        } else {
            serializer.serialize_str(&format!(
                "(bitstring: {} bits)",
                self.len * 8 - self.unused as usize,
            ))
        }
    }
}

impl<'a> From<BitString<'a>> for BitStr {
    fn from(b: BitString) -> Self {
        BitStr {
            len: b.data.len(),
            unused: b.unused_bits,
        }
    }
}

pub struct PrivateBitStr {
    pub len: usize,
    pub unused: u8,
}

impl Serialize for PrivateBitStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.unused == 0 {
            serializer.serialize_str(&format!("(PRIVATE bitstring: {} bytes)", self.len))
        } else {
            serializer.serialize_str(&format!(
                "(PRIVATE bitstring: {} bits)",
                self.len * 8 - self.unused as usize,
            ))
        }
    }
}

impl<'a> From<BitString<'a>> for PrivateBitStr {
    fn from(b: BitString) -> Self {
        PrivateBitStr {
            len: b.data.len(),
            unused: b.unused_bits,
        }
    }
}
