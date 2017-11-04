use std::iter::repeat;
use rand::{self, Rng};
use chacha12::ChaCha12;
use symmetriccipher::SynchronousStreamCipher;

pub fn prg(seed : &mut Seed) {
    assert!(consts::KEY_BYTES == consts::SEED_BYTES);
    let mut rng = rand::thread_rng();
    let nonce: Vec<u8> = repeat(rng.gen::<u8>()).take(24).collect();
    let mut c = ChaCha12::new(&seed.key[..], &nonce[..]);

    // Zero-out the output buffer
    seed.output = [0; consts::SEEDOUT_BYTES as usize];

    c.process(&seed.input, &mut seed.output);
}
