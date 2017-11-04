use sphincs256::consts::*;

pub type MessageHash = [u8; MSGHASH_BYTES as usize];
pub type Rnd = [u8; RND_BYTES as usize];
pub type Root = [u8; HASH_BYTES as usize];
pub type Hash256 = [u8; HASH_BYTES as usize];
pub type Hash512 = [u8; (HASH_BYTES * 2) as usize];
pub type Masks = [u8; N_MASKS as usize];
pub type PrivateKey = [u8; PVTKEY_BYTES as usize];
pub type PublicKey = [u8; PUBKEY_BYTES as usize];
pub type Seed = [u8; SEED_BYTES as usize];
pub type SeedKey = [u8; SEED_BYTES as usize];
pub type SphincsSignature = [u8; SIG_BYTES as usize];
pub type HorstSignature = [u8; HORST_SIGBYTES as usize]; 
