pub const SUBTREE_HEIGHT : u8 = 5;
pub const TOTALTREE_HEIGHT : u8 = 60;
pub const N_LEVELS : u8 = TOTALTREE_HEIGHT / SUBTREE_HEIGHT;
pub const SEED_BYTES : u8 =  32;
pub const HASH_BYTES : u8 = 32;
pub const MSGHASH_BYTES : u8 =  64;
pub const CRYPTO_STREAM_KEYBYTES : u8 = 32;
pub const KEY_BYTES : u8 = 32;
pub const RND_BYTES : u8 = 8;
pub const N_MASKS : u8 = 32;
pub const PVTKEY_BYTES : u16 =  1088;
pub const PUBKEY_BYTES : u16 =  1056;
pub const SIG_BYTES : u16 =  41000;

// HORST Constants
pub const HORST_LOGT : u8 = 16;
pub const HORST_T : u32 = 1u32 << HORST_LOGT;
pub const HORST_K : u8 = 32;
pub const HORST_SKBYTES : u8 = 32;
pub const SEEDOUT_BYTES : u16 = (HORST_T as u16 * HORST_SKBYTES as u16);
pub const HORST_SIGBYTES : u16 = (64u16 * HASH_BYTES as u16) + (HORST_K as u16 * (HORST_SKBYTES as u16 + ((HORST_LOGT - 6) as u16 * HASH_BYTES as u16)));

// WOTS++ Constants
pub const WOTS_LOGW : u8 = 4;
pub const WOTS_W : u8 =  1u8 << WOTS_LOGW;
