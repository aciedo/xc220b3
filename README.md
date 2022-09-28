# `xc220b3`

xc220b3 is a quantum-safe cryptographic library based around a **XC**ha**C**ha**20**-**B**LAKE**3** authenticated cipher. It includes various other things too, for example, wrappers for key exchange protocols and JWT-like certificates that are needed.

## XChaCha20-BLAKE3

This is a custom authenticated cipher used for symmetrical encryption. It is based on the [XChaCha20](https://tools.ietf.org/html/draft-arciszewski-xchacha-03) stream cipher and the [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function. It has some notable differences against ChaCha20-Poly1305, the most popular alternative using the ChaCha cipher.

- It's nonce is 192 bits instead of 96 bits, which means it can be used for longer periods of time without rekeying.
- The nonce is not a counter, or a random number. Instead, it uses the 24-byte BLAKE3 MAC for the nonce.
- This ensures nonces are never reused on the same key for two different messages, while not suffering from slowdowns experienced with random nonces.
- There is less state for a session to store (it only needs the symmetric key).
- It also saves space in messages, as additional data is not appended to the cipher during encryption apart from the MAC.

## Key Exchange

TODO. Aiming to be quantum-safe.
