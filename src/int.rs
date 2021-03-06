use asn1_rs::Integer;
use num_bigint::BigInt;
use serde::Serialize;

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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match *self {
            DisplayedInt::Big { len } => {
                serializer.serialize_str(&format!("(integer: {} bytes)", len))
            }
            DisplayedInt::Small(ref value) => {
                serializer.serialize_str(&("0x".to_string() + &value.to_str_radix(16)))
            }
        }
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let len = self.len;
        serializer.serialize_str(&format!("(PRIVATE integer: {} bytes)", len))
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
