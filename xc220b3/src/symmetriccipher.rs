use crate::buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crate::cryptoutil::symm_enc_or_dec;

pub trait BlockEncryptor {
    fn block_size(&self) -> usize;
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockEncryptorX8 {
    fn block_size(&self) -> usize;
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptor {
    fn block_size(&self) -> usize;
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn block_size(&self) -> usize;
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait Encryptor {
    fn encrypt(
        &mut self,
        input: &mut RefReadBuffer,
        output: &mut RefWriteBuffer,
        eof: bool,
    ) -> BufferResult;
}

pub trait Decryptor {
    fn decrypt(
        &mut self,
        input: &mut RefReadBuffer,
        output: &mut RefWriteBuffer,
        eof: bool,
    ) -> BufferResult;
}

pub trait SynchronousStreamCipher {
    fn process(&mut self, input: &[u8], output: &mut [u8]);
}

// TODO - Its a bit unclear to me why this is necessary
impl SynchronousStreamCipher for Box<dyn SynchronousStreamCipher + 'static> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        let me = &mut **self;
        me.process(input, output);
    }
}

impl Encryptor for Box<dyn SynchronousStreamCipher + 'static> {
    fn encrypt(
        &mut self,
        input: &mut RefReadBuffer,
        output: &mut RefWriteBuffer,
        _: bool,
    ) -> BufferResult {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Box<dyn SynchronousStreamCipher + 'static> {
    fn decrypt(
        &mut self,
        input: &mut RefReadBuffer,
        output: &mut RefWriteBuffer,
        _: bool,
    ) -> BufferResult {
        symm_enc_or_dec(self, input, output)
    }
}
