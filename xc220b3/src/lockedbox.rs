use blake3::Hasher;
use core::iter::repeat;
#[cfg(feature = "tracing")]
use tracing::{info_span, trace};

use crate::{mac::MAC, symmetriccipher::SynchronousStreamCipher, xc220::XC220};

pub struct LockedBox {
    key: [u8; 32],
    xcc20: XC220,
    b3: Hasher,
}

#[derive(Debug)]
pub enum LockedBoxError {
    MacMismatch,
}

impl LockedBox {
    /// Creates a new LockedBox with a random ephemeral secret using provided
    /// RNG.
    pub fn new(seed: [u8; 32]) -> LockedBox {
        let mut b3 = Hasher::new();
        b3.update(&seed);
        let key: [u8; 32] = b3.finalize().into();
        b3.reset();

        LockedBox {
            key,
            xcc20: XC220::new(&[0; 32], &[0; 24]),
            b3,
        }
    }

    pub fn encrypt(&mut self, plain: Vec<u8>) -> Vec<u8> {
        cfg_if!(
            if #[cfg(feature = "tracing")] {
                let span = info_span!("encrypt");
                let _enter = span.enter();
            }
        );

        #[cfg(feature = "tracing")]
        trace!("start");
        let mac = self.mac(&plain);
        #[cfg(feature = "tracing")]
        trace!("MAC: {}", mac.to_hex());

        #[cfg(feature = "tracing")]
        trace!("allocating for {}byte output", plain.len());
        let mut output: Vec<u8> = repeat(0).take(plain.len()).collect();
        #[cfg(feature = "tracing")]
        trace!("encrypting");
        self.xcc20 = XC220::new(&self.key, mac.as_bytes());
        self.xcc20.process(&plain[..], &mut output[..]);
        #[cfg(feature = "tracing")]
        trace!("extending with mac");
        output.extend_from_slice(mac.as_bytes());
        #[cfg(feature = "tracing")]
        trace!("done");
        output
    }

    pub fn decrypt(&mut self, mut ciphertext: Vec<u8>) -> Result<Vec<u8>, LockedBoxError> {
        cfg_if!(
            if #[cfg(feature = "tracing")] {
                let span = info_span!("decrypt");
                let _enter = span.enter();
            }
        );

        #[cfg(feature = "tracing")]
        trace!("start");

        let claimed_mac = MAC::from(ciphertext.split_off(ciphertext.len() - 24));
        #[cfg(feature = "tracing")]
        trace!("allocating for {}byte output", ciphertext.len());
        let mut output: Vec<u8> = repeat(0).take(ciphertext.len()).collect();
        #[cfg(feature = "tracing")]
        trace!("creating new chacha");
        self.xcc20 = XC220::new(&self.key, claimed_mac.as_bytes());
        #[cfg(feature = "tracing")]
        trace!("encrypting");
        self.xcc20.process(&ciphertext[..], &mut output[..]);

        #[cfg(feature = "tracing")]
        trace!("calculating our own mac");
        let calculated_mac = self.mac(&output);
        #[cfg(feature = "tracing")]
        trace!("checking mac");
        if claimed_mac != calculated_mac {
            #[cfg(feature = "tracing")]
            trace!("Claimed MAC: {}", claimed_mac.to_hex());
            #[cfg(feature = "tracing")]
            trace!("Calculated MAC: {}", calculated_mac.to_hex());
            return Err(LockedBoxError::MacMismatch);
        } else {
            #[cfg(feature = "tracing")]
            trace!("mac good 👍");
        }
        #[cfg(feature = "tracing")]
        trace!("done");
        Ok(output)
    }

    fn mac(&mut self, plain: &[u8]) -> MAC {
        self.b3.update(plain);
        self.b3.update(&self.key);

        let mut reader = self.b3.finalize_xof();
        let hash = MAC::from_output_reader(&mut reader);
        self.b3.reset();
        hash
    }
}

cfg_if! {
    if #[cfg(feature = "tracing")] {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";

// u8 array to hex string using lookup table
fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0xf) as usize] as char);
    }
    hex
}
    }
}
