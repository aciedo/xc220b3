// why do we use this over BLAKE3's `Hash` struct?

// we use a 24 byte hash because it's the same size as the nonce for XChaCha20
// the `Hash` type is 32 bytes, which means we can't use it

// the `OutputReader` we use for the 24 byte output can't be used for the
// constant-time equality checks we need for the mac check during decryption
// for security, so this is a modified version of the `Hash` type for 24 bytes
// minus some functionality we aren't using

use arrayvec::ArrayString;
use blake3::OutputReader;
use constant_time_eq::constant_time_eq;

pub struct MAC([u8; 24]);

impl MAC {
    /// The raw bytes of the `Hash`. Note that byte arrays don't provide
    /// constant-time equality checking, so use `MAC` instead.
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

impl From<MAC> for [u8; 24] {
    #[inline]
    fn from(hash: MAC) -> Self {
        hash.0
    }
}

impl From<Vec<u8>> for MAC {
    #[inline]
    fn from(bytes: Vec<u8>) -> Self {
        let mut hash = [0u8; 24];
        hash.copy_from_slice(&bytes[..24]);
        Self(hash)
    }
}

/// This implementation is constant-time.
impl PartialEq for MAC {
    #[inline]
    fn eq(&self, other: &MAC) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

/// This implementation is constant-time.
impl PartialEq<[u8; 24]> for MAC {
    #[inline]
    fn eq(&self, other: &[u8; 24]) -> bool {
        constant_time_eq(&self.0, other)
    }
}

/// This implementation is constant-time.
impl PartialEq<MAC> for [u8; 24] {
    #[inline]
    fn eq(&self, other: &MAC) -> bool {
        constant_time_eq(&other.0, self)
    }
}

/// This implementation is constant-time if the target is 32 bytes long.
impl PartialEq<[u8]> for MAC {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        constant_time_eq(&self.0, other)
    }
}

impl Eq for MAC {}
