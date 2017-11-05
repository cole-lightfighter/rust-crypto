mod consts;

use consts::*;
use blake2s::Blake2s;
use digest::Digest;

pub fn varlen_hash(inp: &[u8]) -> [u8; HASH_BYTES as usize] {
    assert!(SEED_BYTES == HASH_BYTES, "Need to have SEED_BYTES == HASH_BYTES");
    let mut sh = Blake2s::new(32);
    let mut out = [0u8; HASH_BYTES as usize];
    sh.input(inp);
    sh.result(&mut out[..]);
    
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn works_with_multiple_input_len() {
        let _ = varlen_hash(&[0u8]);
        let _ = varlen_hash(&[0u8; 2]);
        let _ = varlen_hash(&[0u8; 16]);
        let _ = varlen_hash(&[0u8; 256]);
        let _ = varlen_hash(&[0u8; 1024]);
    }
}
