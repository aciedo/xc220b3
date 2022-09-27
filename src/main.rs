use core::str;
use crypto::chacha20::ChaCha20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use k256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand::thread_rng;
use rand::Rng;
use rand_core::OsRng;
use std::{env, iter::repeat}; // requires 'getrandom' feature

struct Session {
    ready: bool,
    secret: EphemeralSecret,
    pk: EncodedPoint,
    key: [u8; 32],
    nonce: [u8; 8],
    counter: u64,
    cc20: ChaCha20,
    b3: blake3::Hasher,
}

impl Session {
    fn new() -> Session {
        let secret = EphemeralSecret::random(&mut OsRng);
        let pk = secret.public_key();
        Session {
            ready: false,
            secret: secret,
            pk: EncodedPoint::from(pk),
            key: [0; 32],
            nonce: [0; 8],
            counter: 0,
            cc20: ChaCha20::new(&[0; 32], &[0; 8]),
            b3: blake3::Hasher::new(),
        }
    }

    fn set_sym_key(&mut self, pk: &EncodedPoint) {
        if self.ready {
            panic!("Session already ready");
        }

        let pk = PublicKey::from_sec1_bytes(pk.as_ref()).expect("public key is invalid!");
        let shared = self.secret.diffie_hellman(&pk);
        let shared_bytes = shared.raw_secret_bytes();

        self.b3.update(shared_bytes);
        self.key = self.b3.finalize().as_bytes().clone();
        self.b3.reset();
        self.cc20 = ChaCha20::new(&self.key, &[0; 8]);
        self.ready = true;
    }

    fn increase_counter(&mut self) {
        self.counter += 1;
        self.nonce.copy_from_slice(&self.counter.to_be_bytes());
        self.cc20 = ChaCha20::new(&self.key, &self.nonce);
    }

    fn encrypt(&mut self, plain: Vec<u8>) -> Vec<u8> {
        if !self.ready {
            panic!("session not ready!")
        };

        self.increase_counter();
        println!("[ENC] plain (hex): {}", hex::encode(plain.clone()));
        // mac
        let mac = self.mac(&plain);
        println!("[ENC] MAC: {}", hex::encode(mac));

        let mut output: Vec<u8> = repeat(0).take(plain.len()).collect();
        self.cc20.process(&plain[..], &mut output[..]);
        output.extend_from_slice(&mac);
        output
    }

    fn decrypt(&mut self, mut ciphertext: Vec<u8>) -> Vec<u8> {
        if !self.ready {
            panic!("session not ready!")
        };
        self.increase_counter();

        println!("[DEC] cipher: {}", hex::encode(ciphertext.clone()));

        // claimed mac is last 16 bytes
        let claimed_mac: Vec<u8> = ciphertext.split_off(ciphertext.len() - 16);
        println!("[DEC] Claimed MAC: {}", hex::encode(claimed_mac.clone()));

        let mut output: Vec<u8> = repeat(0).take(ciphertext.len()).collect();
        self.cc20.process(&ciphertext[..], &mut output[..]);

        println!("[DEC] plain (hex): {}", hex::encode(output.clone()));
        match str::from_utf8(&output) {
            Ok(v) => println!("[DEC] plain: {}", v),
            Err(e) => println!("[DEC] Invalid UTF-8 sequence: {}", e),
        };

        // calculate our own mac of the plain
        let calculated_mac = self.mac(&output);
        if claimed_mac != calculated_mac {
            println!("[DEC] Claimed MAC: {}", hex::encode(claimed_mac));
            println!("[DEC] Calculated MAC: {}", hex::encode(calculated_mac));
            panic!("MAC mismatch. Message has been tampered with.");
        } else {
            println!("[DEC] MAC looks good ✅");
        }

        output
    }

    fn mac(&mut self, plain: &[u8]) -> [u8; 16] {
        if !self.ready {
            panic!("session not ready!")
        };

        self.b3.update(plain);
        self.b3.update(&self.key);
        self.b3.update(&self.nonce);

        let mut mac = [0u8; 16];
        self.b3.finalize_xof().fill(&mut mac);
        self.b3.reset();

        mac
    }
}

fn main() {
    let mut key: [u8; 32] = [0; 32];
    thread_rng().fill(&mut key);

    let mut msg = "Hello";
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        msg = args[1].as_str();
    }

    println!("== c220b3 demo ==");
    println!("Message: {:?}", msg);

    let mut sesh1 = Session::new();
    let mut sesh2 = Session::new();

    // give each session the other's secp256k1 public key so they can derive a
    // shared secret, which is hashed to get the symmetric key (technically ECDHE)

    sesh1.set_sym_key(&sesh2.pk);
    sesh2.set_sym_key(&sesh1.pk);

    // when this happens in production, we're using a variation of certificates
    // to exchange the public keys between live signers and valera's server.
    // live signers are given a certificate that contains their public key
    // and a signature of that from valera. the live signer knows the long-term
    // public keys for valera, so they verify that they're talking to valid peers
    // before we give each session the other's public key.

    let plain = msg.as_bytes().to_vec();

    let encrypted_bytes = sesh1.encrypt(plain.clone());

    sesh2.decrypt(encrypted_bytes.clone());

    // pretend to change eight random bytes in the encrypted message
    let mut tampered_bytes = sesh1.encrypt(plain.clone());
    tamper_with(&mut tampered_bytes, 8);

    println!(
        "\nTampered Encrypted: {}",
        hex::encode(tampered_bytes.clone())
    );

    // Decrypting
    let decrypted_bytes2 = sesh2.decrypt(tampered_bytes.clone());
    println!(
        "\nDecrypted: {}",
        str::from_utf8(&decrypted_bytes2[..]).unwrap()
    );
}

fn tamper_with(bytes: &mut Vec<u8>, many_times: usize) {
    let mut rng = thread_rng();
    let mut index;

    for _ in 0..many_times {
        index = rng.gen_range(0..bytes.len());
        bytes[index] = rng.gen();
    }
}
