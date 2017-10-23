use sphincs256_helpers::{consts, Seed, prg};
use consts::*;

pub struct Horst {
    t : u32,
    k : u8,
    sk : Vec<u8>,
    signature : Vec<u8>,
    seed : Seed,
}

impl Horst {
    pub fn new(seed: Seed) -> Horst {
        Horst {
            t : HORST_T,
            k : HORST_K,
            sk : vec![0; HORST_SKBYTES as usize],
            signature : vec![0; HORST_SIGBYTES as usize],
            seed : Seed { 
                key : seed.key, 
                input : seed.input, 
                output : vec![0; SEEDOUT_BYTES as usize],
            }
        }
    }

    pub fn expand_seed(&mut self) {
        prg(&mut self.seed);
    }
}
