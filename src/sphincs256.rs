use digest::Digest;
use blake2s::Blake2s;
use sphincs256_helpers::consts::*;


pub struct LeafAddress {
    level: u64,
    subtree: u64,
    subleaf: u64,
}

pub struct Sphincs256 {
    /// n: bitlength of hashes in WOTS+ and HORST (256)
    n: u16,
    /// m: bitlength of message hash (512)
    m: u16,
    /// h: height of the hyper-tree (60)
    h: u8,
    /// d: layers of the hyper-tree (12)
    d: u8,
    /// w: Winternitz parameter used for WOTS signatures (16)
    w: u8,
    R: Vec<u8>,
    message_hash: Vec<u8>,
    rnd: Vec<u64>,
    root: Vec<u8>,
    seed: Vec<u8>,
    masks: Vec<u8>,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl Sphincs256 {
    pub fn new() -> Sphincs256 {
        Sphincs256 {
            n: (HASH_BYTES as u16 * 8u16),
            m: (MSGHASH_BYTES as u16 * 8u16),
            h: TOTALTREE_HEIGHT,
            d: N_LEVELS,
            w: WOTS_W,
            R: vec![0; SEED_BYTES as usize],
            message_hash: vec![0; MSGHASH_BYTES as usize],
            rnd: vec![0; RND_BYTES as usize],
            root: vec![0; HASH_BYTES as usize],
            seed: vec![0; SEED_BYTES as usize],
            masks: vec![0; (N_MASKS as usize * HASH_BYTES as usize)],
            private_key: vec![0; PVTKEY_BYTES as usize],
            public_key: vec![0; PUBKEY_BYTES as usize],
            signature: vec![0; SIG_BYTES as usize],
        }
    }

    pub fn get_seed(&mut self, sk: &[u8; SEED_BYTES as usize], leafaddr: &LeafAddress) {
        let mut buffer: Vec<u8> = sk.to_vec();

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

        assert!(SEED_BYTES == HASH_BYTES);
        let mut sh = Blake2s::new(32);
        buffer.append(&mut bufftail);
        sh.input(&mut buffer[..]);
        sh.result(&mut self.seed);
    }
}

#[cfg(test)]
mod test {
    use sphincs256::Sphincs256;
    use sphincs256_helpers::consts::*;

    #[test]
    fn sphincs256_init() {
        let mut sp256 = Sphincs256::new();
        assert_eq!(PVTKEY_BYTES, sp256.private_key.len() as u16);
        assert_eq!(PUBKEY_BYTES, sp256.public_key.len() as u16);
        assert_eq!(SIG_BYTES, sp256.signature.len() as u16);
    }
}
