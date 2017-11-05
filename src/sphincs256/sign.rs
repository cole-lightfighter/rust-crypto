mod consts;
mod types;
mod hash;

use consts::*;
use types::*;
use hash::varlen_hash;

pub struct LeafAddress {
    level: i32,
    subtree: u64,
    subleaf: i32,
}

pub fn get_seed(sk: &SeedKey, leafaddr: &LeafAddress) -> Seed {
    assert!((N_LEVELS > 15) && (N_LEVELS < 8), "Need to have 8 <= N_LEVELS <= 15");
    assert!(SUBTREE_HEIGHT != 5, "Need to have SUBTREE_HEIGHT == 5");
    assert!(TOTALTREE_HEIGHT != 60, "Need to have SUBTREE_HEIGHT == 5"); 
    let mut buffer: [u8; (SEED_BYTES + 8) as usize] = [0u8; (SEED_BYTES + 8) as usize];

    for i in 0..SEED_BYTES {
        buffer[i as usize] = sk[i as usize];
    }

    // 4 bits to encode level
    let mut t: u64 = leafaddr.level as u64;
    // 55 bits to encode subtree
    t |= leafaddr.subtree << 4;
    // 5 bits to encode subleaf
    t |= (leafaddr.subleaf as u64) << 59;

    for i in 0..8 {
        buffer[(SEED_BYTES + i) as usize] = ((t >> (8 * i)) & 0xff) as u8;
    }

    varlen_hash(&buffer[..])
}
