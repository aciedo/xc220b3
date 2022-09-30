// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::{cmp, ptr};

#[derive(Clone,Copy)]
pub enum BufferResult {
    BufferUnderflow,
    BufferOverflow
}

pub trait ReadBuffer {
    fn is_empty(&self) -> bool;
    fn is_full(&self) -> bool;
    fn remaining(&self) -> usize;
    fn capacity(&self) -> usize;
    fn position(&self) -> usize { self.capacity() - self.remaining() }

    fn rewind(&mut self, distance: usize);
    fn truncate(&mut self, amount: usize);
    fn reset(&mut self);

    fn peek_next(&self, count: usize) -> &[u8];
    fn peek_remaining(&self) -> &[u8] {
        self.peek_next(self.remaining())
    }

    fn take_next(&mut self, count: usize) -> &[u8];
    fn take_remaining(&mut self) -> &[u8] {
        let rem = self.remaining();
        self.take_next(rem)
    }

    fn push_to<W: WriteBuffer>(&mut self, output: &mut W) {
        let count = cmp::min(output.remaining(), self.remaining());
        {
            let src = self.take_next(count);
            let dst: &mut [u8] = output.take_next(count);
            assert!(dst.len() >= src.len());
            unsafe {
                let srcp = src.as_ptr();
                let dstp = dst.as_mut_ptr();
                ptr::copy_nonoverlapping(srcp, dstp, src.len());
            }
        };
    }
}

pub trait WriteBuffer {
    fn is_empty(&self) -> bool;
    fn is_full(&self) -> bool;
    fn remaining(&self) -> usize;
    fn capacity(&self) -> usize;
    fn position(&self) -> usize { self.capacity() - self.remaining() }

    fn rewind(&mut self, distance: usize);
    fn reset(&mut self);

    // FIXME - Shouldn't need mut self
    fn peek_read_buffer(&mut self) -> RefReadBuffer;

    fn take_next(&mut self, count: usize) -> &mut [u8];
    fn take_remaining(&mut self) -> &mut [u8] {
        let rem = self.remaining();
        self.take_next(rem)
    }
    fn take_read_buffer(&mut self) -> RefReadBuffer;
}

pub struct RefReadBuffer<'a> {
    buff: &'a [u8],
    pos: usize
}

impl <'a> RefReadBuffer<'a> {
    pub fn new(buff: &[u8]) -> RefReadBuffer {
        RefReadBuffer {
            buff: buff,
            pos: 0
        }
    }
}

impl <'a> ReadBuffer for RefReadBuffer<'a> {
    fn is_empty(&self) -> bool { self.pos == self.buff.len() }
    fn is_full(&self) -> bool { self.pos == 0 }
    fn remaining(&self) -> usize { self.buff.len() - self.pos }
    fn capacity(&self) -> usize { self.buff.len() }

    fn rewind(&mut self, distance: usize) { self.pos -= distance; }
    fn truncate(&mut self, amount: usize) {
        self.buff = &self.buff[..self.buff.len() - amount];
    }
    fn reset(&mut self) { self.pos = 0; }

    fn peek_next(&self, count: usize) -> &[u8] { &self.buff[self.pos..count] }

    fn take_next(&mut self, count: usize) -> &[u8] {
        let r = &self.buff[self.pos..self.pos + count];
        self.pos += count;
        r
    }
}

pub struct RefWriteBuffer<'a> {
    buff: &'a mut [u8],
    len: usize,
    pos: usize
}

impl <'a> WriteBuffer for RefWriteBuffer<'a> {
    fn is_empty(&self) -> bool { self.pos == 0 }
    fn is_full(&self) -> bool { self.pos == self.len }
    fn remaining(&self) -> usize { self.len - self.pos }
    fn capacity(&self) -> usize { self.len }

    fn rewind(&mut self, distance: usize) { self.pos -= distance; }
    fn reset(&mut self) { self.pos = 0; }

    fn peek_read_buffer(&mut self) -> RefReadBuffer {
        RefReadBuffer::new(&mut self.buff[..self.pos])
    }

    fn take_next(&mut self, count: usize) -> &mut [u8] {
        let r = &mut self.buff[self.pos..self.pos + count];
        self.pos += count;
        r
    }
    fn take_read_buffer(&mut self) -> RefReadBuffer {
        let r = RefReadBuffer::new(&mut self.buff[..self.pos]);
        self.pos = 0;
        r
    }
}
