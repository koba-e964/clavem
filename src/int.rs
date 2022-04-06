use asn1_rs::Integer;
use num_bigint::BigInt;
use serde_lite::{Intermediate, Serialize};

/// Displayed integers. If the value is too big, its summary is displayed instead.
pub enum DisplayedInt {
    Big {
        len: usize, // size in bytes
    },
    Small(BigInt),
}

impl DisplayedInt {
    pub fn from_bigint(value: BigInt, threshold: usize) -> Self {
        if value.bits() >= 8 * threshold as u64 {
            DisplayedInt::Big {
                len: ((value.bits() + 7) / 8) as usize,
            }
        } else {
            DisplayedInt::Small(value)
        }
    }
}

impl Serialize for DisplayedInt {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::String(match *self {
            DisplayedInt::Big { len } => {
                format!("(integer: {} bytes)", len)
            }
            DisplayedInt::Small(ref value) => "0x".to_string() + &value.to_str_radix(16),
        }))
    }
}

impl From<BigInt> for DisplayedInt {
    fn from(value: BigInt) -> Self {
        Self::from_bigint(value, 4) // an arbitrary threshold
    }
}

impl From<u32> for DisplayedInt {
    fn from(value: u32) -> Self {
        DisplayedInt::Small(value.into())
    }
}

impl<'a> From<Integer<'a>> for DisplayedInt {
    fn from(value: Integer<'a>) -> Self {
        value.as_bigint().into()
    }
}

/// Private integers. Its summary is displayed instead of its content.
pub struct PrivateInt {
    len: usize,
}

impl Serialize for PrivateInt {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        let len = self.len;
        Ok(Intermediate::String(format!(
            "(PRIVATE integer: {} bytes)",
            len
        )))
    }
}

impl<'a> From<&'_ Integer<'a>> for PrivateInt {
    fn from(value: &Integer<'a>) -> Self {
        Self {
            len: ((value.as_bigint().bits() + 7) / 8) as usize,
        }
    }
}
impl From<Integer<'_>> for PrivateInt {
    fn from(value: Integer) -> Self {
        (&value).into()
    }
}
