
use ripemd::Ripemd160;
use sha2::{Sha256, Digest};
pub fn s256(src: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(&src);
    let hash_val = hash.finalize();
    let sli = hash_val.as_slice();
    Vec::from(sli)
}

pub fn double256(src: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(&src);
    let h1 = hash.finalize_reset();
    hash.update(h1);
    let h2 = hash.finalize();
    h2.to_vec()
}

pub fn checksum(version: u8, input: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.push(version);
    buf.append(&mut input.to_vec());
    let check = double256(buf.as_slice());
    check.as_slice()[..4].to_vec()
}

// rip160
pub fn ripemd160(src: &[u8]) -> Vec<u8> {
    let mut r160 = Ripemd160::new();
    r160.update(src);
    let rip_hash = r160.finalize();
    rip_hash.to_vec()
}