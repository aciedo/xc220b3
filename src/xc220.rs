use core::cmp;

use crate::buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crate::symmetriccipher::{Encryptor, Decryptor, SynchronousStreamCipher, SymmetricCipherError};
use crate::cryptoutil::{read_u32_le, symm_enc_or_dec, write_u32_le, xor_keystream};
use crate::simd::u32x4;

#[derive(Clone,Copy)]
struct ChaChaState {
  a: u32x4,
  b: u32x4,
  c: u32x4,
  d: u32x4
}

#[derive(Copy)]
pub struct XC220 {
    state  : ChaChaState,
    output : [u8; 64],
    offset : usize,
}

impl Clone for XC220 { fn clone(&self) -> XC220 { *self } }

macro_rules! swizzle{
    ($b: expr, $c: expr, $d: expr) => {{
        let u32x4(b10, b11, b12, b13) = $b;
        $b = u32x4(b11, b12, b13, b10);
        let u32x4(c10, c11, c12, c13) = $c;
        $c = u32x4(c12, c13,c10, c11);
        let u32x4(d10, d11, d12, d13) = $d;
        $d = u32x4(d13, d10, d11, d12);
    }}
}

macro_rules! state_to_buffer {
    ($state: expr, $output: expr) => {{
        let u32x4(a1, a2, a3, a4) = $state.a;
        let u32x4(b1, b2, b3, b4) = $state.b;
        let u32x4(c1, c2, c3, c4) = $state.c;
        let u32x4(d1, d2, d3, d4) = $state.d;
        let lens = [
            a1,a2,a3,a4,
            b1,b2,b3,b4,
            c1,c2,c3,c4,
            d1,d2,d3,d4
        ];
        for i in 0..lens.len() {
            write_u32_le(&mut $output[i*4..(i+1)*4], lens[i]);
        }
    }}
}

macro_rules! round{
    ($state: expr) => {{
      $state.a = $state.a + $state.b;
      rotate!($state.d, $state.a, S16);
      $state.c = $state.c + $state.d;
      rotate!($state.b, $state.c, S12);
      $state.a = $state.a + $state.b;
      rotate!($state.d, $state.a, S8);
      $state.c = $state.c + $state.d;
      rotate!($state.b, $state.c, S7);
    }}
}

macro_rules! rotate {
    ($a: expr, $b: expr, $c:expr) => {{
      let v = $a ^ $b;
      let r = S32 - $c;
      let right = v >> r;
      $a = (v << $c) ^ right
    }}
}

static S32:u32x4 = u32x4(32, 32, 32, 32);
static S16:u32x4 = u32x4(16, 16, 16, 16);
static S12:u32x4 = u32x4(12, 12, 12, 12);
static S8:u32x4 = u32x4(8, 8, 8, 8);
static S7:u32x4 = u32x4(7, 7, 7, 7);

impl XC220 {
    pub fn new(key: &[u8], nonce: &[u8]) -> XC220 {
        assert!(key.len() == 32);
        assert!(nonce.len() == 24);

        // HChaCha20 produces a 256-bit output block starting from a 512 bit
        // input block where (x0,x1,...,x15) where
        //
        //  * (x0, x1, x2, x3) is the XC220 constant.
        //  * (x4, x5, ... x11) is a 256 bit key.
        //  * (x12, x13, x14, x15) is a 128 bit nonce.
        let mut xc220 = XC220{ state: XC220::expand(key, &nonce[0..16]), output: [0u8; 64], offset: 64 };

        // Use HChaCha to derive the subkey, and initialize a XC220 instance
        // with the subkey and the remaining 8 bytes of the nonce.
        let mut new_key = [0; 32];
        xc220.hchacha20(&mut new_key);
        xc220.state = XC220::expand(&new_key, &nonce[16..24]);

        xc220
    }

    fn expand(key: &[u8], nonce: &[u8]) -> ChaChaState {

        let constant = match key.len() {
            16 => b"expand 16-byte k",
            32 => b"expand 32-byte k",
            _  => unreachable!(),
        };
        ChaChaState {
            a: u32x4(
                read_u32_le(&constant[0..4]),
                read_u32_le(&constant[4..8]),
                read_u32_le(&constant[8..12]),
                read_u32_le(&constant[12..16])
            ),
            b: u32x4(
                read_u32_le(&key[0..4]),
                read_u32_le(&key[4..8]),
                read_u32_le(&key[8..12]),
                read_u32_le(&key[12..16])
            ),
            c: if key.len() == 16 {
                    u32x4(
                        read_u32_le(&key[0..4]),
                        read_u32_le(&key[4..8]),
                        read_u32_le(&key[8..12]),
                        read_u32_le(&key[12..16])
                    )
                } else {
                    u32x4(
                        read_u32_le(&key[16..20]),
                        read_u32_le(&key[20..24]),
                        read_u32_le(&key[24..28]),
                        read_u32_le(&key[28..32])
                    )
                },
            d: if nonce.len() == 16 {
                   u32x4(
                        read_u32_le(&nonce[0..4]),
                        read_u32_le(&nonce[4..8]),
                        read_u32_le(&nonce[8..12]),
                        read_u32_le(&nonce[12..16])
                    )
               } else if nonce.len() == 12 {
                   u32x4(
                        0,
                        read_u32_le(&nonce[0..4]),
                        read_u32_le(&nonce[4..8]),
                        read_u32_le(&nonce[8..12])
                    )
               } else {
                   u32x4(
                        0,
                        0,
                        read_u32_le(&nonce[0..4]),
                        read_u32_le(&nonce[4..8])
                    )
               }
        }
    }

    fn hchacha20(&mut self, out: &mut [u8]) -> () {
        let mut state = self.state;

        // Apply r/2 iterations of the same "double-round" function,
        // obtaining (z0, z1, ... z15) = doubleround r/2 (x0, x1, ... x15).
        for _ in 0..10 {
            round!(state);
            let u32x4(b10, b11, b12, b13) = state.b;
            state.b = u32x4(b11, b12, b13, b10);
            let u32x4(c10, c11, c12, c13) = state.c;
            state.c = u32x4(c12, c13,c10, c11);
            let u32x4(d10, d11, d12, d13) = state.d;
            state.d = u32x4(d13, d10, d11, d12);
            round!(state);
            let u32x4(b20, b21, b22, b23) = state.b;
            state.b = u32x4(b23, b20, b21, b22);
            let u32x4(c20, c21, c22, c23) = state.c;
            state.c = u32x4(c22, c23, c20, c21);
            let u32x4(d20, d21, d22, d23) = state.d;
            state.d = u32x4(d21, d22, d23, d20);
        }

        // HChaCha20 then outputs the 256-bit block (z0, z1, z2, z3, z12, z13,
        // z14, z15).  These correspond to the constant and input positions in
        // the ChaCha matrix.
        let u32x4(a1, a2, a3, a4) = state.a;
        let u32x4(d1, d2, d3, d4) = state.d;
        let lens = [
            a1,a2,a3,a4,
            d1,d2,d3,d4
        ];
        for i in 0..lens.len() {
            write_u32_le(&mut out[i*4..(i+1)*4], lens[i]);
        }
    }

    // put the the next 64 keystream bytes into self.output
    fn update(&mut self) {
        let mut state = self.state;

        for _ in 0..10 {
            round!(state);
            swizzle!(state.b, state.c, state.d);
            round!(state);
            swizzle!(state.d, state.c, state.b);
        }
        state.a = state.a + self.state.a;
        state.b = state.b + self.state.b;
        state.c = state.c + self.state.c;
        state.d = state.d + self.state.d;

        state_to_buffer!(state, self.output);

        self.state.d = self.state.d + u32x4(1, 0, 0, 0);
        let u32x4(c12, _, _, _) = self.state.d;
        if c12 == 0 {
            // we could increment the other counter word with an 8 byte nonce
            // but other implementations like boringssl have this same
            // limitation
            panic!("counter is exhausted");
        }

        self.offset = 0;
    }
}

impl SynchronousStreamCipher for XC220 {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        let len = input.len();
        let mut i = 0;
        while i < len {
            // If there is no keystream available in the output buffer,
            // generate the next block.
            if self.offset == 64 {
                self.update();
            }

            // Process the min(available keystream, remaining input length).
            let count = cmp::min(64 - self.offset, len - i);
            xor_keystream(&mut output[i..i+count], &input[i..i+count], &self.output[self.offset..]);
            i += count;
            self.offset += count;
        }
    }
}

impl Encryptor for XC220 {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for XC220 {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod test {
    use core::iter::repeat;

    use crate::xc220::XC220;
    use crate::symmetriccipher::SynchronousStreamCipher;

    #[test]
    fn test_chacha20_256_tls_vectors() {
        struct TestVector {
            key:   [u8; 32],
            nonce: [u8; 8],
            keystream: Vec<u8>,
        };
        // taken from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
        let test_vectors = vec!(
            TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                nonce: [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
                keystream: vec!(
                    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
                    0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
                    0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
                    0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
                    0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
                    0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
                    0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
                    0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
                ),
            }, TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
                nonce: [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
                keystream: vec!(
                    0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96,
                    0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e, 0x3c, 0x96,
                    0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60,
                    0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41,
                    0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2,
                    0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
                    0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81,
                    0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63,
                ),
            }, TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                nonce: [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ],
                keystream: vec!(
                    0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5,
                    0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f, 0x65, 0x3a,
                    0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13,
                    0x4f, 0xcb, 0x7d, 0xf1, 0x37, 0x82, 0x10, 0x31,
                    0xe8, 0x5a, 0x05, 0x02, 0x78, 0xa7, 0x08, 0x45,
                    0x27, 0x21, 0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b,
                    0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e,
                    0x44, 0x5f, 0x41, 0xe3,
                ),
            }, TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                nonce: [ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
                keystream: vec!(
                    0xef, 0x3f, 0xdf, 0xd6, 0xc6, 0x15, 0x78, 0xfb,
                    0xf5, 0xcf, 0x35, 0xbd, 0x3d, 0xd3, 0x3b, 0x80,
                    0x09, 0x63, 0x16, 0x34, 0xd2, 0x1e, 0x42, 0xac,
                    0x33, 0x96, 0x0b, 0xd1, 0x38, 0xe5, 0x0d, 0x32,
                    0x11, 0x1e, 0x4c, 0xaf, 0x23, 0x7e, 0xe5, 0x3c,
                    0xa8, 0xad, 0x64, 0x26, 0x19, 0x4a, 0x88, 0x54,
                    0x5d, 0xdc, 0x49, 0x7a, 0x0b, 0x46, 0x6e, 0x7d,
                    0x6b, 0xbd, 0xb0, 0x04, 0x1b, 0x2f, 0x58, 0x6b,
                ),
            }, TestVector{
                key: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                nonce: [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ],
                keystream: vec!(
                    0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69,
                    0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b, 0xb7, 0x75,
                    0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93,
                    0xec, 0x01, 0xac, 0x56, 0xf8, 0x5a, 0xc3, 0xc1,
                    0x34, 0xa4, 0x54, 0x7b, 0x73, 0x3b, 0x46, 0x41,
                    0x30, 0x42, 0xc9, 0x44, 0x00, 0x49, 0x17, 0x69,
                    0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1,
                    0x59, 0x16, 0x15, 0x5c, 0x2b, 0xe8, 0x24, 0x1a,
                    0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc, 0x35, 0x94,
                    0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66,
                    0x89, 0xde, 0x95, 0x26, 0x49, 0x86, 0xd9, 0x58,
                    0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd,
                    0x9a, 0x5a, 0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56,
                    0x3e, 0xb9, 0xb3, 0xa4, 0xa4, 0x72, 0xf8, 0x2e,
                    0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e,
                    0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0, 0x31, 0xc7,
                    0x9d, 0xb9, 0xd4, 0xf7, 0xc7, 0xa8, 0x99, 0x15,
                    0x1b, 0x9a, 0x47, 0x50, 0x32, 0xb6, 0x3f, 0xc3,
                    0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a,
                    0x97, 0xa5, 0xf5, 0x76, 0xfe, 0x06, 0x40, 0x25,
                    0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5,
                    0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69,
                    0x59, 0x66, 0x09, 0x96, 0x54, 0x6c, 0xc9, 0xc4,
                    0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7,
                    0x0e, 0xaf, 0x46, 0xf7, 0x6d, 0xad, 0x39, 0x79,
                    0xe5, 0xc5, 0x36, 0x0c, 0x33, 0x17, 0x16, 0x6a,
                    0x1c, 0x89, 0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a,
                    0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2,
                    0xcc, 0xb2, 0x7d, 0x5a, 0xaa, 0xe0, 0xad, 0x7a,
                    0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b, 0x54, 0x09,
                    0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a,
                    0x6d, 0xeb, 0x3a, 0xb7, 0x8f, 0xab, 0x78, 0xc9,
                ),
            },
        );

        for tv in test_vectors.iter() {
            let mut c = XC220::new(&tv.key, &tv.nonce);
            let input: Vec<u8> = repeat(0).take(tv.keystream.len()).collect();
            let mut output: Vec<u8> = repeat(0).take(input.len()).collect();
            c.process(&input[..], &mut output[..]);
            assert_eq!(output, tv.keystream);
        }
    }

    #[test]
    fn test_xc220_basic() {
        // There aren't any convenient test vectors for XChaCha/20,
        // so, a simple test case was generated using Andrew Moon's
        // chacha-opt library, with the key/nonce from test_salsa20_cryptopp().
        let key =
            [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
             0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
             0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
             0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89];
        let nonce =
            [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
             0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
             0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37];
        let input = [0u8; 139];
        let mut stream = [0u8; 139];
        let result =
            [0x4f, 0xeb, 0xf2, 0xfe, 0x4b, 0x35, 0x9c, 0x50,
             0x8d, 0xc5, 0xe8, 0xb5, 0x98, 0x0c, 0x88, 0xe3,
             0x89, 0x46, 0xd8, 0xf1, 0x8f, 0x31, 0x34, 0x65,
             0xc8, 0x62, 0xa0, 0x87, 0x82, 0x64, 0x82, 0x48,
             0x01, 0x8d, 0xac, 0xdc, 0xb9, 0x04, 0x17, 0x88,
             0x53, 0xa4, 0x6d, 0xca, 0x3a, 0x0e, 0xaa, 0xee,
             0x74, 0x7c, 0xba, 0x97, 0x43, 0x4e, 0xaf, 0xfa,
             0xd5, 0x8f, 0xea, 0x82, 0x22, 0x04, 0x7e, 0x0d,
             0xe6, 0xc3, 0xa6, 0x77, 0x51, 0x06, 0xe0, 0x33,
             0x1a, 0xd7, 0x14, 0xd2, 0xf2, 0x7a, 0x55, 0x64,
             0x13, 0x40, 0xa1, 0xf1, 0xdd, 0x9f, 0x94, 0x53,
             0x2e, 0x68, 0xcb, 0x24, 0x1c, 0xbd, 0xd1, 0x50,
             0x97, 0x0d, 0x14, 0xe0, 0x5c, 0x5b, 0x17, 0x31,
             0x93, 0xfb, 0x14, 0xf5, 0x1c, 0x41, 0xf3, 0x93,
             0x83, 0x5b, 0xf7, 0xf4, 0x16, 0xa7, 0xe0, 0xbb,
             0xa8, 0x1f, 0xfb, 0x8b, 0x13, 0xaf, 0x0e, 0x21,
             0x69, 0x1d, 0x7e, 0xce, 0xc9, 0x3b, 0x75, 0xe6,
             0xe4, 0x18, 0x3a];

        let mut xc220 = XC220::new(&key, &nonce);
        xc220.process(&input, &mut stream);
        assert!(stream[..] == result[..]);
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;
    use symmetriccipher::SynchronousStreamCipher;
    use xc220::XC220;

    #[bench]
    pub fn chacha20_10(bh: & mut Bencher) {
        let mut xc220 = XC220::new(&[0; 32], &[0; 8]);
        let input = [1u8; 10];
        let mut output = [0u8; 10];
        bh.iter( || {
            xc220.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn chacha20_1k(bh: & mut Bencher) {
        let mut xc220 = XC220::new(&[0; 32], &[0; 8]);
        let input = [1u8; 1024];
        let mut output = [0u8; 1024];
        bh.iter( || {
            xc220.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn chacha20_64k(bh: & mut Bencher) {
        let mut xc220 = XC220::new(&[0; 32], &[0; 8]);
        let input = [1u8; 65536];
        let mut output = [0u8; 65536];
        bh.iter( || {
            xc220.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }
}
