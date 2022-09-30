use core::str;
use rand::{thread_rng, Rng};
use tracing::{error, info};

use xc220b3::{Session, SessionError};

fn main() -> Result<(), SessionError> {
    tracing_subscriber::fmt::init();

    let mut key: [u8; 32] = [0; 32];
    thread_rng().fill(&mut key);

    let msg = "Hello";

    info!("== xc220b3 demo ==");
    info!("Message: {:?}", msg);

    let mut rng = thread_rng();
    let mut sesh1 = Session::new(&mut rng);
    let mut sesh2 = Session::new(&mut rng);

    // these would be usually communicated out of band in a cert
    let sesh1pk = sesh1.pk().unwrap();
    let sesh2pk = sesh2.pk().unwrap();

    // give each session the other's secp256k1 public key so they can derive a
    // shared secret, which is hashed to get the symmetric key (technically ECDHE)

    sesh1.set_sym_key(&sesh2pk)?;
    sesh2.set_sym_key(&sesh1pk)?;

    // when this happens in production, we're using a variation of certificates
    // to exchange the public keys between live signers and valera's server.
    // live signers are given a certificate that contains their public key
    // and a signature of that from valera. the live signer knows the long-term
    // public keys for valera, so they verify that they're talking to valid peers
    // before we give each session the other's public key.

    let plain = msg.as_bytes().to_vec();

    let encrypted_bytes = sesh1.encrypt(plain.clone());

    match sesh2.decrypt(encrypted_bytes.clone()) {
        Ok(plain) => {
            info!("Decrypted: {:?}", str::from_utf8(&plain[..]).unwrap());
        }
        Err(e) => {
            error!("Error: {:?}", e);
        }
    };

    info!("Now attempting message modification...");

    let mut tampered_bytes = sesh1.encrypt(plain.clone());
    tamper_with(&mut tampered_bytes, 1);

    info!(
        "Tampered Encrypted: {}",
        hex::encode(tampered_bytes.clone())
    );

    match sesh2.decrypt(tampered_bytes) {
        Ok(_) => (),
        Err(e) => match e {
            SessionError::MacMismatch => {
                info!("MAC mismatch! Message was tampered with! (expected)")
            },
            _ => error!("Wrong error received")
        },
    };

    Ok(())
}

fn tamper_with(bytes: &mut Vec<u8>, many_times: usize) {
    let mut rng = thread_rng();
    let mut index;

    for _ in 0..many_times {
        index = rng.gen_range(0..bytes.len());
        bytes[index] = rng.gen();
    }
}
