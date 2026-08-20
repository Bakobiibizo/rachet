use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};

/// A lowercase hexadecimal SHA-256 integrity digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntegrityHash([u8; 32]);

impl IntegrityHash {
    /// Hashes the exact supplied bytes.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for IntegrityHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for IntegrityHash {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err("a SHA-256 hash must contain exactly 64 lowercase hex characters");
        }

        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for IntegrityHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IntegrityHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

fn nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("a SHA-256 hash must use lowercase hexadecimal"),
    }
}

#[cfg(test)]
mod tests {
    use super::IntegrityHash;

    #[test]
    fn strict_hash_encoding_round_trips() {
        let hash = IntegrityHash::digest(b"rachet fixture");
        let encoded = serde_json::to_string(&hash).unwrap();
        let decoded: IntegrityHash = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, hash);
        assert_eq!(hash.to_string().len(), 64);

        for invalid in [
            "00",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            assert!(invalid.parse::<IntegrityHash>().is_err());
        }
    }
}
