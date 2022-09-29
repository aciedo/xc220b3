use core::fmt;
use arrayvec::ArrayString;
use blake3::OutputReader;
use constant_time_eq::constant_time_eq;

pub struct Hash24([u8; 24]);

impl Hash24 {
    /// The raw bytes of the `Hash`. Note that byte arrays don't provide
    /// constant-time equality checking, so if  you need to compare hashes,
    /// prefer the `Hash` type.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    pub fn from_output_reader(reader: &mut OutputReader) -> Self {
        let mut hash = [0u8; 24];
        reader.fill(&mut hash);
        Self(hash)
    }

    pub fn to_hex(&self) -> ArrayString<{ 2 * 24 }> {
        let mut s = ArrayString::new();
        let table = b"0123456789abcdef";
        for &b in self.0.iter() {
            s.push(table[(b >> 4) as usize] as char);
            s.push(table[(b & 0xf) as usize] as char);
        }
        s
    }
}

impl From<Hash24> for [u8; 24] {
    #[inline]
    fn from(hash: Hash24) -> Self {
        hash.0
    }
}

/// This implementation is constant-time.
impl PartialEq for Hash24 {
    #[inline]
    fn eq(&self, other: &Hash24) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

/// This implementation is constant-time.
impl PartialEq<[u8; 24]> for Hash24 {
    #[inline]
    fn eq(&self, other: &[u8; 24]) -> bool {
        constant_time_eq(&self.0, other)
    }
}

/// This implementation is constant-time.
impl PartialEq<Hash24> for [u8; 24] {
    #[inline]
    fn eq(&self, other: &Hash24) -> bool {
        constant_time_eq(&other.0, self)
    }
}

/// This implementation is constant-time if the target is 32 bytes long.
impl PartialEq<[u8]> for Hash24 {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        constant_time_eq(&self.0, other)
    }
}

impl Eq for Hash24 {}

impl fmt::Display for Hash24 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Formatting field as `&str` to reduce code size since the `Debug`
        // dynamic dispatch table for `&str` is likely needed elsewhere already,
        // but that for `ArrayString<[u8; 64]>` is not.
        let hex = self.to_hex();
        let hex: &str = hex.as_str();

        f.write_str(hex)
    }
}

impl fmt::Debug for Hash24 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Formatting field as `&str` to reduce code size since the `Debug`
        // dynamic dispatch table for `&str` is likely needed elsewhere already,
        // but that for `ArrayString<[u8; 64]>` is not.
        let hex = self.to_hex();
        let hex: &str = hex.as_str();

        f.debug_tuple("Hash").field(&hex).finish()
    }
}