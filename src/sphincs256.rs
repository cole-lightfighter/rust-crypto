use std::iter::repeat;

use digest::Digest;
use rand::{self, Rng};
use blake2s::Blake2s;
use chacha12::ChaCha12;
use symmetriccipher::SynchronousStreamCipher;

macro_rules! define_const {
    ($name: ident, $value: expr) 
    => 
    (macro_rules! $name {
        () => ($value)
    });
}

// SPHINCS256 Constants 
define_const!(SUBTREE_HEIGHT, 5);
define_const!(TOTALTREE_HEIGHT, 60);
define_const!(N_LEVELS, TOTALTREE_HEIGHT!() / SUBTREE_HEIGHT!());
define_const!(SEED_BYTES, 32);
define_const!(HASH_BYTES, 32);
define_const!(MSGHASH_BYTES, 64);
define_const!(KEY_BYTES, 32);
define_const!(RND_BYTES, 8);
define_const!(N_MASKS, 32);
define_const!(PVTKEY_BYTES, 1088);
define_const!(PUBKEY_BYTES, 1056);
define_const!(SIG_BYTES, 41000);

// HORST Constants
define_const!(HORST_LOGT, 16);
define_const!(HORST_T, (1u32 << HORST_LOGT!()));
define_const!(HORST_K, 32);
define_const!(HORST_SKBYTES, 32);
define_const!(HORST_SIGBYTES, (64 * HASH_BYTES!()) + 
                                ( HORST_K!() *
                                  ( HORST_SKBYTES!() +
                                    ((HORST_LOGT!()-6) * HASH_BYTES!())
                                  )
                                )
);

// WOTS++ Constants
define_const!(WOTS_LOGW, 4);
define_const!(WOTS_W, 1u8 << WOTS_LOGW!() );


pub struct LeafAddress {
    level : u64,
    subtree : u64,
    subleaf : u64,
}

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
    R : [u8; SEED_BYTES!()],
    message_hash : [u8; MSGHASH_BYTES!()],
    rnd : [u64; RND_BYTES!()],
    horst_sigbytes : u64,
    root : [u8; HASH_BYTES!()],
    seed : [u8; SEED_BYTES!()],
    masks : [u8; N_MASKS!()*HASH_BYTES!()],
    private_key : [u8; PVTKEY_BYTES!()],
    public_key : [u8; PUBKEY_BYTES!()],
    signature : [u8; SIG_BYTES!()],
}

impl Sphincs256 {
    pub fn new() -> Sphincs256 {
        Sphincs256 {
          n : HASH_BYTES!() * 8,
          m : MSGHASH_BYTES!() * 8,
          h : TOTALTREE_HEIGHT!(),
          d : N_LEVELS!(), 
          w : WOTS_W!(),
          t : HORST_T!(),
          k : HORST_K!(),
          R : [0; SEED_BYTES!()],
          message_hash : [0; MSGHASH_BYTES!()],
          rnd : [0; RND_BYTES!()],
          horst_sigbytes : HORST_SIGBYTES!(),
          root : [0; HASH_BYTES!()],
          seed : [0; SEED_BYTES!()],
          masks : [0; N_MASKS!()*HASH_BYTES!()], 
          private_key : [0; PVTKEY_BYTES!()],
          public_key : [0; PUBKEY_BYTES!()],
          signature : [0; SIG_BYTES!()],
        }
    }

    fn prg(input: &[u8], output: &mut [u8], key: &[u8; KEY_BYTES!()]) {
        assert!(input.len() == output.len());
        let mut rng = rand::thread_rng();
        let nonce: Vec<u8> = repeat(rng.gen::<u8>()).take(24).collect();
        let mut c = ChaCha12::new(key, &nonce[..]);

        c.process(input, &mut output[..]);
    }

    pub fn get_seed(&mut self, sk: &[u8; SEED_BYTES!()], leafaddr: &LeafAddress) {
       let mut buffer : Vec<u8> = sk.to_vec(); 

       // 4 bits to encode level
       let mut t = leafaddr.level;
       // 55 bits to encode subtree
       t |= (leafaddr.subtree << 4) as u64;
       // 5 bits to encode subleaf
       t |= (leafaddr.subleaf << 59) as u64;
       
       let mut bufftail = vec![0; 8];
       let btlen = bufftail.len();
       for idx in 0..btlen {
           bufftail[idx] = ((t >> (8 * idx)) & 0xff) as u8; 
       }

       assert!(SEED_BYTES!() == HASH_BYTES!());
       let mut sh = Blake2s::new(32);
       buffer.append(&mut bufftail);
       sh.input(&mut buffer[..]);
       sh.result(&mut self.seed);
    }
}
