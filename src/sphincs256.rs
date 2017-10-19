use std::iter::repeat;

use rand::{self, Rng};
use chacha12::ChaCha12;
use symmetriccipher::SynchronousStreamCipher;

pub struct Sphincs256 {
    /// n: bitlength of hashes in WOTS+ and HORST (256)
    n : u16,
    /// m: bitlength of message hash (512)
    m : u16,
    /// h: height of the hyper-tree (60)
    h : u8,
    /// d: layers of the hyper-tree (12)
    d : u8,
    /// w: Winternitz parameter used for WOTS signatures (16)
    w : u8,
    /// t: number of secret-key elements of HORST (2^16 == 65536)
    t : u32,
    /// k: number of revealed secret-key elements per HORST sig (32)
    k : u8,
}

impl Sphincs256 {
    pub fn new() -> Sphincs256 {
        Sphincs256 {
          n : 256,
          m : 512,
          h : 60,
          d : 12,
          w : 16,
          t : 65536,
          k : 32,
        }
    }

    fn prg(input: &[u8], output: &mut [u8], key: &[u8; 32]) {
        assert!(input.len() == output.len());
        let mut rng = rand::thread_rng();
        let nonce: Vec<u8> = repeat(rng.gen::<u8>()).take(24).collect();
        let mut c = ChaCha12::new(key, &nonce[..]);

        c.process(input, &mut output[..]);
    }
}
