use base58::ToBase58;
use k256::{
    ecdsa::{SigningKey}
};
use rand_core::OsRng;
mod crypto;
use crypto::hash;
fn main() {
    let sign_key = SigningKey::random(&mut OsRng);
    let binding = sign_key.to_bytes();
    let pri_key_bt = binding.as_slice();
    let pri = hex::encode(pri_key_bt);
    println!("{}, len: {}", pri, pri.len());

    let pub_key = sign_key.verifying_key();
    let binding = pub_key.to_bytes();
    let pub_key_bt = binding.as_slice();
    let puk = hex::encode(pub_key_bt);
    println!("puk: {}, len: {}", puk, puk.len());

    // sha256
    let h256 = hash::s256(pub_key_bt);
    // rip160
    let rip_hash = hash::ripemd160(h256.as_slice());
    // check num
    let check_hash = hash::checksum(0, rip_hash.as_slice());

    let mut buf: [u8; 1+20+4] = [0;25];
    buf[1..21].copy_from_slice(rip_hash.as_slice());
    buf[21..].copy_from_slice(&check_hash[..]);

    println!("{:?}", buf.to_base58());

}


