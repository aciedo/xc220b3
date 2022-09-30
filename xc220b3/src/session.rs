use blake3::Hasher;
use k256::{ecdh::EphemeralSecret, EncodedPoint, elliptic_curve::PublicKey};
use rand::{CryptoRng, RngCore};
use tracing::{trace, info_span};
use core::iter::repeat;

use crate::{mac::MAC, xc220::XC220, symmetriccipher::SynchronousStreamCipher};

pub struct Session {
    ready: bool,
    secret: Option<EphemeralSecret>,
    key: [u8; 32],
    cc20: XC220,
    b3: Hasher,
}

#[derive(Debug)]
pub enum SessionError {
    MacMismatch,
    InvalidPubKey,
    EmptySecret
}

impl Session {
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Session {
        Session {
            ready: false,
            secret: Some(EphemeralSecret::random(rng)),
            key: [0; 32],
            cc20: XC220::new(&[0; 32], &[0; 24]),
            b3: Hasher::new(),
        }
    }

    pub fn set_sym_key(&mut self, pk: &EncodedPoint) -> Result<(), SessionError> {
        if self.ready {
            panic!("Session already ready");
        }

        let span = info_span!("set_sym_key");
        let _enter = span.enter();

        let pk = match PublicKey::from_sec1_bytes(pk.as_ref()) {
            Ok(pk) => pk,
            Err(_) => return Err(SessionError::InvalidPubKey)
        };
        let shared = {
            let this = self.secret.as_ref();
            match this {
                Some(val) => val,
                None => return Err(SessionError::EmptySecret),
            }
        }.diffie_hellman(&pk);
        let shared_bytes = shared.raw_secret_bytes();

        self.b3.update(shared_bytes);
        self.key = self.b3.finalize().as_bytes().clone();
        self.b3.reset();
        self.cc20 = XC220::new(&self.key, &[0; 24]);
        #[cfg(feature = "tracing")]
        trace!("session ready");
        self.ready = true;
        self.secret = None;
        Ok(())
    }

    pub fn encrypt(&mut self, plain: Vec<u8>) -> Vec<u8> {
        if !self.ready {
            panic!("session not ready!")
        };

        let span = info_span!("encrypt");
        let _enter = span.enter();

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
        self.cc20 = XC220::new(&self.key, mac.as_bytes());
        self.cc20.process(&plain[..], &mut output[..]);
        #[cfg(feature = "tracing")]
        trace!("extending with mac");
        output.extend_from_slice(mac.as_bytes());
        #[cfg(feature = "tracing")]
        trace!("done");
        output
    }

    pub fn decrypt(&mut self, mut ciphertext: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        if !self.ready {
            panic!("session not ready!")
        };

        let span = info_span!("decrypt");
        let _enter = span.enter();

        #[cfg(feature = "tracing")]
        trace!("start");

        let claimed_mac = MAC::from(ciphertext.split_off(ciphertext.len() - 24));
        #[cfg(feature = "tracing")]
        trace!("allocating for {}byte output", ciphertext.len());
        let mut output: Vec<u8> = repeat(0).take(ciphertext.len()).collect();
        #[cfg(feature = "tracing")]
        trace!("creating new chacha");
        self.cc20 = XC220::new(&self.key, claimed_mac.as_bytes());
        #[cfg(feature = "tracing")]
        trace!("encrypting");
        self.cc20.process(&ciphertext[..], &mut output[..]);

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
            return Err(SessionError::MacMismatch);
        } else {
            #[cfg(feature = "tracing")]
            trace!("mac good 👍");
        }
        #[cfg(feature = "tracing")]
        trace!("done");
        Ok(output)
    }

    fn mac(&mut self, plain: &[u8]) -> MAC {
        if !self.ready {
            panic!("session not ready!")
        };

        self.b3.update(plain);
        self.b3.update(&self.key);

        let mut reader = self.b3.finalize_xof();
        let hash = MAC::from_output_reader(&mut reader);
        self.b3.reset();
        hash
    }

    pub fn pk(&self) -> Result<EncodedPoint, SessionError> {
        if self.secret.is_none() {
            Err(SessionError::EmptySecret)
        } else {
            Ok(EncodedPoint::from(self.secret.as_ref().unwrap().public_key()))
        }
    }
}
