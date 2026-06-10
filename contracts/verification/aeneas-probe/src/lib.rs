#![no_std]
pub const N: usize = 16;
pub const K: usize = 13;
pub const SIG: usize = 4008;

#[inline]
fn write16(sig: &mut [u8; SIG], offset: usize, block: &[u8; N]) {
    sig[offset..offset + N].copy_from_slice(block);
}

// A: helper call in while loop, row passed via direct nested-array borrow
pub fn shape_a(rows: &[[u8; N]; K]) -> [u8; SIG] {
    let mut sig = [0u8; SIG];
    let mut offset = 0;
    let mut t = 0;
    while t < K {
        write16(&mut sig, offset, &rows[t]);
        offset += N;
        t += 1;
    }
    sig
}

// B: row copied by value first, then helper call
pub fn shape_b(rows: &[[u8; N]; K]) -> [u8; SIG] {
    let mut sig = [0u8; SIG];
    let mut offset = 0;
    let mut t = 0;
    while t < K {
        let row = rows[t];
        write16(&mut sig, offset, &row);
        offset += N;
        t += 1;
    }
    sig
}

// C: per-byte copy with single-variable running index
pub fn shape_c(rows: &[[u8; N]; K]) -> [u8; SIG] {
    let mut sig = [0u8; SIG];
    let mut w = 0;
    let mut t = 0;
    while t < K {
        let row = rows[t];
        let mut b = 0;
        while b < N {
            sig[w] = row[b];
            w += 1;
            b += 1;
        }
        t += 1;
    }
    sig
}

// D: per-byte copy, compound index offset + b
pub fn shape_d(rows: &[[u8; N]; K]) -> [u8; SIG] {
    let mut sig = [0u8; SIG];
    let mut offset = 0;
    let mut t = 0;
    while t < K {
        let row = rows[t];
        let mut b = 0;
        while b < N {
            sig[offset + b] = row[b];
            b += 1;
        }
        offset += N;
        t += 1;
    }
    sig
}

// E: owned-to-owned byte copy, single index each
pub fn shape_e(src: &[u8; 32]) -> [u8; 128] {
    let mut dst = [0u8; 128];
    let mut w = 64;
    let mut b = 0;
    while b < 32 {
        dst[w] = src[b];
        w += 1;
        b += 1;
    }
    dst
}

pub const A: usize = 11;

fn dummy_tree(t: u32) -> ([u8; N], [[u8; N]; A]) {
    ([t as u8; N], [[0u8; N]; A])
}

// F: the real sign_inner FORS-section structure — shuffled dynamic-index
// row writes from a tuple-returning call, then the write16 serialization.
pub fn shape_f(order: &[u8; 64]) -> [u8; SIG] {
    let mut sig = [0u8; SIG];
    let mut offset = 0;

    let mut fors_secrets = [[0u8; N]; K];
    let mut fors_auth_paths = [[[0u8; N]; A]; K - 1];

    for step in 0..(K - 1) {
        let t = order[step] as usize;
        let (secret, auth_path) = dummy_tree(t as u32);
        fors_secrets[t] = secret;
        fors_auth_paths[t] = auth_path;
    }

    let mut t = 0;
    while t < K {
        let row = fors_secrets[t];
        write16(&mut sig, offset, &row);
        offset += N;
        t += 1;
    }

    let mut t = 0;
    while t < K - 1 {
        let mut h = 0;
        while h < A {
            let row = fors_auth_paths[t][h];
            write16(&mut sig, offset, &row);
            offset += N;
            h += 1;
        }
        t += 1;
    }
    sig
}

// G: debug_assert_eq with message (formatting machinery under dev profile)
pub fn shape_g(x: &[u32; 4]) -> u32 {
    debug_assert_eq!(x[3], 0, "Last index must be 0");
    x[0]
}

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// H: fisher_yates verbatim from the real crate
#[inline(never)]
#[must_use]
pub fn shape_h(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut t = 0;
    while t < n {
        buf[t] = t as u8;
        t += 1;
    }
    if seed == &[0u8; 32] || n <= 1 {
        return buf;
    }
    let mut stream = [0u8; 128];
    let mut blk: u32 = 0;
    while blk < 4 {
        let mut h = Sha256::new();
        h.update(b"sphincs-c10-fisher-yates-v1");
        h.update(*seed);
        h.update(blk.to_be_bytes());
        let mut d = [0u8; 32];
        d.copy_from_slice(&h.finalize());
        let mut w = (blk as usize) * 32;
        let mut b = 0;
        while b < 32 {
            stream[w] = d[b];
            w += 1;
            b += 1;
        }
        d.zeroize();
        blk += 1;
    }
    let mut pos = 0;
    let mut i = n - 1;
    while i >= 1 {
        let bound = (i + 1) as u16;
        let lo = stream[pos] as u16;
        let hi = stream[pos + 1] as u16;
        pos += 2;
        let r = (hi << 8) | lo;
        let j = (r % bound) as usize;
        let tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i -= 1;
    }
    stream.zeroize();
    buf
}

pub fn shape_i(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut t = 0;
    while t < n {
        buf[t] = t as u8;
        t += 1;
    }
    if seed == &[0u8; 32] || n <= 1 {
        return buf;
    }
    let mut stream = [0u8; 128];
    let mut blk: u32 = 0;
    while blk < 4 {
        let mut h = Sha256::new();
        h.update(b"sphincs-c10-fisher-yates-v1");
        h.update(*seed);
        h.update(blk.to_be_bytes());
        let mut d = [0u8; 32];
        d.copy_from_slice(&h.finalize());
        let mut w = (blk as usize) * 32;
        let mut b = 0;
        while b < 32 {
            stream[w] = d[b];
            w += 1;
            b += 1;
        }
        blk += 1;
    }
    let mut pos = 0;
    let mut i = n - 1;
    while i >= 1 {
        let bound = (i + 1) as u16;
        let lo = stream[pos] as u16;
        let hi = stream[pos + 1] as u16;
        pos += 2;
        let r = (hi << 8) | lo;
        let j = (r % bound) as usize;
        let tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i -= 1;
    }
    buf
}

pub fn shape_j(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut t = 0;
    while t < n {
        buf[t] = t as u8;
        t += 1;
    }
    if seed == &[0u8; 32] || n <= 1 {
        return buf;
    }
    let mut stream = [0u8; 128];
    let mut blk: u32 = 0;
    while blk < 4 {
        let mut h = Sha256::new();
        h.update(b"sphincs-c10-fisher-yates-v1");
        h.update(*seed);
        h.update(blk.to_be_bytes());
        let mut d = [0u8; 32];
        d.copy_from_slice(&h.finalize());
        let mut w = (blk as usize) * 32;
        let mut b = 0;
        while b < 32 {
            stream[w] = d[b];
            w += 1;
            b += 1;
        }
        blk += 1;
    }
    let mut pos = 0;
    let mut i = n - 1;
    while i >= 1 {
        let bound = (i + 1) as u16;
        let lo = stream[pos] as u16;
        let hi = stream[pos + 1] as u16;
        pos += 2;
        let r = (hi << 8) | lo;
        let j = (r % bound) as usize;
        let tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i -= 1;
    }
    stream.zeroize();
    buf
}

pub fn shape_k(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut t = 0;
    while t < n {
        buf[t] = t as u8;
        t += 1;
    }
    if seed == &[0u8; 32] || n <= 1 {
        return buf;
    }
    let mut stream = [0u8; 128];
    let mut blk: u32 = 0;
    while blk < 4 {
        let d = [blk as u8; 32];
        let mut w = (blk as usize) * 32;
        let mut b = 0;
        while b < 32 {
            stream[w] = d[b];
            w += 1;
            b += 1;
        }
        blk += 1;
    }
    let mut pos = 0;
    let mut i = n - 1;
    while i >= 1 {
        let bound = (i + 1) as u16;
        let lo = stream[pos] as u16;
        let hi = stream[pos + 1] as u16;
        pos += 2;
        let r = (hi << 8) | lo;
        let j = (r % bound) as usize;
        let tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i -= 1;
    }
    buf
}


pub fn shape_l(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut t = 0;
    while t < n {
        buf[t] = t as u8;
        t += 1;
    }
    if seed == &[0u8; 32] || n <= 1 {
        return buf;
    }
    let mut h = Sha256::new();
    h.update(b"sphincs-c10-fisher-yates-v1");
    h.update(*seed);
    let mut d = [0u8; 32];
    d.copy_from_slice(&h.finalize());
    let mut stream = [0u8; 128];
    let mut blk: u32 = 0;
    while blk < 4 {
        let mut w = (blk as usize) * 32;
        let mut b = 0;
        while b < 32 {
            stream[w] = d[b];
            w += 1;
            b += 1;
        }
        blk += 1;
    }
    let mut pos = 0;
    let mut i = n - 1;
    while i >= 1 {
        let bound = (i + 1) as u16;
        let lo = stream[pos] as u16;
        let hi = stream[pos + 1] as u16;
        pos += 2;
        let r = (hi << 8) | lo;
        let j = (r % bound) as usize;
        let tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i -= 1;
    }
    buf
}


pub fn shape_m(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut t = 0;
    while t < n {
        buf[t] = t as u8;
        t += 1;
    }
    let mut stream = [0u8; 128];
    let mut blk: u32 = 0;
    while blk < 4 {
        let d = [blk as u8; 32];
        let mut w = (blk as usize) * 32;
        let mut b = 0;
        while b < 32 {
            stream[w] = d[b];
            w += 1;
            b += 1;
        }
        blk += 1;
    }
    let mut pos = 0;
    let mut i = n - 1;
    while i >= 1 {
        let bound = (i + 1) as u16;
        let lo = stream[pos] as u16;
        let hi = stream[pos + 1] as u16;
        pos += 2;
        let r = (hi << 8) | lo;
        let j = (r % bound) as usize;
        let tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i -= 1;
    }
    buf
}



pub fn shape_n(z: bool, n: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut t = 0;
    while t < n {
        buf[t] = t as u8;
        t += 1;
    }
    if z || n <= 1 {
        return buf;
    }
    let mut stream = [0u8; 128];
    let mut blk: u32 = 0;
    while blk < 4 {
        let d = [blk as u8; 32];
        let mut w = (blk as usize) * 32;
        let mut b = 0;
        while b < 32 {
            stream[w] = d[b];
            w += 1;
            b += 1;
        }
        blk += 1;
    }
    let mut pos = 0;
    let mut i = n - 1;
    while i >= 1 {
        let bound = (i + 1) as u16;
        let lo = stream[pos] as u16;
        let hi = stream[pos + 1] as u16;
        pos += 2;
        let r = (hi << 8) | lo;
        let j = (r % bound) as usize;
        let tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i -= 1;
    }
    buf
}


