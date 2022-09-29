use blake3::Hasher;
use crypto::{chacha20::ChaCha20, symmetriccipher::SynchronousStreamCipher};
use k256::{ecdh::EphemeralSecret, EncodedPoint, elliptic_curve::PublicKey};
use rand::{CryptoRng, RngCore};
use tracing::{debug, info_span};
use core::iter::repeat;
use std::convert::TryInto;

use crate::hash24::Hash24;

pub struct Session {
    ready: bool,
    secret: Option<EphemeralSecret>,
    key: [u8; 32],
    cc20: ChaCha20,
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
            cc20: ChaCha20::new_xchacha20(&[0; 32], &[0; 24]),
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
        self.cc20 = ChaCha20::new_xchacha20(&self.key, &[0; 24]);
        debug!("session ready");
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

        debug!("start");
        let mac = self.mac(&plain);
        debug!("MAC: {}", mac.to_hex());

        debug!("allocating for {}byte output", plain.len());
        let mut output: Vec<u8> = repeat(0).take(plain.len()).collect();
        debug!("encrypting");
        self.cc20 = ChaCha20::new_xchacha20(&self.key, mac.as_bytes());
        self.cc20.process(&plain[..], &mut output[..]);
        debug!("extending with mac");
        output.extend_from_slice(mac.as_bytes());
        debug!("done");
        output
    }

    pub fn decrypt(&mut self, mut ciphertext: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        if !self.ready {
            panic!("session not ready!")
        };

        let span = info_span!("decrypt");
        let _enter = span.enter();

        debug!("start");

        let claimed_mac: [u8; 24] = ciphertext.split_off(ciphertext.len() - 24).try_into().unwrap();
        debug!("allocating for {}byte output", ciphertext.len());
        let mut output: Vec<u8> = repeat(0).take(ciphertext.len()).collect();
        debug!("creating new chacha");
        self.cc20 = ChaCha20::new_xchacha20(&self.key, &claimed_mac);
        debug!("encrypting");
        self.cc20.process(&ciphertext[..], &mut output[..]);

        debug!("calculating our own mac");
        let calculated_mac = self.mac(&output);
        debug!("checking mac");
        if claimed_mac != calculated_mac {
            debug!("Claimed MAC: {}", hex::encode(claimed_mac));
            debug!("Calculated MAC: {}", calculated_mac.to_hex());
            return Err(SessionError::MacMismatch);
        } else {
            debug!("mac good 👍");
        }
        debug!("done");
        Ok(output)
    }

    fn mac(&mut self, plain: &[u8]) -> Hash24 {
        if !self.ready {
            panic!("session not ready!")
        };

        self.b3.update(plain);
        self.b3.update(&self.key);

        let mut reader = self.b3.finalize_xof();
        let hash = Hash24::from_output_reader(&mut reader);
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
