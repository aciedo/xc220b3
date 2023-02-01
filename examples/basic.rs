use rand::{thread_rng, Rng, RngCore};
use tracing::{error, info};

use xc220b3::{LockedBox, LockedBoxError, Session, SessionError};

fn main() -> Result<(), SessionError> {
    tracing_subscriber::fmt::init();

    info!("== xc220b3 demo ==");

    let mut rng = thread_rng();
    let mut sesh1 = Session::new(&mut rng);
    let mut sesh2 = Session::new(&mut rng);

    // these would be usually communicated out of band in a cert
    let sesh1pk = sesh1.pk()?;
    let sesh2pk = sesh2.pk()?;

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

    let mut data: Vec<u8> = vec![0; 256 * 1024 * 1024];
    rng.fill_bytes(&mut data);

    let data_len = data.len();
    let start = std::time::Instant::now();
    let encrypted_bytes = sesh1.encrypt(data);
    info!(
        "Encrypt MB/s: {:?}",
        (data_len as f64 / start.elapsed().as_secs_f64()) / 1000.0 / 1000.0
    );

    let start = std::time::Instant::now();
    match sesh2.decrypt(encrypted_bytes) {
        Ok(_) => {
            info!("Decrypted");
        }
        Err(e) => {
            error!("Error: {:?}", e);
        }
    };
    info!(
        "Decrypt MB/s: {:?}",
        (data_len as f64 / start.elapsed().as_secs_f64()) / 1000.0 / 1000.0
    );

    // info!("Now attempting message modification...");

    // let mut tampered_bytes = sesh1.encrypt(&data);
    // tamper_with(&mut tampered_bytes, 1);

    // match sesh2.decrypt(tampered_bytes) {
    //     Ok(_) => (),
    //     Err(e) => match e {
    //         SessionError::MacMismatch => {
    //             info!("MAC mismatch! Message was tampered with! (expected)")
    //         },
    //         _ => error!("Wrong error received")
    //     },
    // };

    // LockedBox
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    let mut lb = LockedBox::new(key);

    // generate 512 MB of random data to encrypt
    let mut data: Vec<u8> = vec![0; 256 * 1024 * 1024];
    rng.fill_bytes(&mut data);

    let encrypted_bytes = lb.encrypt(data);

    match lb.decrypt(encrypted_bytes) {
        Ok(_) => {
            info!("Decrypted");
        }
        Err(e) => {
            error!("Error: {:?}", e);
        }
    };

    // info!("Now attempting data modification...");

    // let mut tampered_bytes = encrypted_bytes;
    // tamper_with(&mut tampered_bytes, 1);

    // match lb.decrypt(tampered_bytes) {
    //     Ok(_) => (),
    //     Err(e) => match e {
    //         LockedBoxError::MacMismatch => {
    //             info!("MAC mismatch! Data was tampered with! (expected)")
    //         },
    //     },
    // };

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
