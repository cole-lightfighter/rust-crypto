mod consts;

use std::iter::repeat;
use rand::{self, Rng};

use consts::*;
use chacha12::ChaCha12;
use symmetriccipher::SynchronousStreamCipher;

pub fn prg(r: &[u8], key: &[u8; KEY_BYTES as usize]) -> [u8; 64] {
    assert!(KEY_BYTES == SEED_BYTES, "SEED_BYTES needs to match CRYPTO_STREAM_KEYBYTES for this implementation");
    let nonce = [0u8; 12]; 
    let mut chacha = ChaCha12::new(&key[..], &nonce);

    let output = [0; 64];

    chacha.process(&seed.input, &mut output);
    chacha.output
}
