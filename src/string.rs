use asn1_rs::BitString;
use serde_lite::{Intermediate, Serialize};

pub struct BitStr {
    pub len: usize,
    pub unused: u8,
}

impl Serialize for BitStr {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::String(if self.unused == 0 {
            format!("(bitstring: {} bytes)", self.len)
        } else {
            format!("(bitstring: {} bits)", self.len * 8 - self.unused as usize,)
        }))
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
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::String(if self.unused == 0 {
            format!("(PRIVATE bitstring: {} bytes)", self.len)
        } else {
            format!(
                "(PRIVATE bitstring: {} bits)",
                self.len * 8 - self.unused as usize,
            )
        }))
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
