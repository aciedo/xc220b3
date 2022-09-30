# `xc220b3`

### Demo

```sh
RUST_LOG=debug cargo run --release --example basic
```
_For the losers who use Windows_

```
$env RUST_LOG=debug
cargo run --release --example basic
```

### Usage

```sh
cargo add xc220b3
```

Look at `basic.rs` in `examples` for usage.

---

**Note:** This has not been audited. Use at your own risk. This is a work in progress for internal use at Valera. It is likely to change and need optimisations to achieve its goals.

xc220b3 is a (planned-to-be-quantum-safe) cryptographic library based around a **XC**ha**C**ha**20**-**B**LAKE**3** authenticated cipher. It (will) include various other things too, for example, wrappers for key exchange protocols and JWT-like certificates that are needed.

The API design is opinionated - instead of returning structs, it returns bytes which are intended for direct out-of-bound transmission. You provide the transport and in/out (including serialization) and the library secures whatever you're sending.

## XChaCha20-BLAKE3

This is a custom authenticated cipher used for symmetrical encryption. It is based on the [XChaCha20](https://tools.ietf.org/html/draft-arciszewski-xchacha-03) stream cipher and the [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function. It has some notable functional differences against ChaCha20-Poly1305, the most popular alternative using the ChaCha cipher (apart from using different ciphers, of course):

- The nonce is not a counter, or a random number. Instead, it uses the 24-byte BLAKE3 MAC for the nonce.
- This ensures nonces are never reused on the same key for two different messages, while not suffering from slowdowns experienced with random nonces.
- There is less state for a session to store (it only needs the symmetric key).
- It also saves space in messages, as additional data is not appended to the cipher during encryption apart from the MAC.
- BLAKE3 can be significantly faster than Poly1305, dropping down to 0.49 cycles per byte on modern hardware vs ~2.5 cycles per byte for Poly1305 for 16KB+ messages (5x improvement).

## Key Exchange

Not ready yet. Aiming to be quantum-safe.
