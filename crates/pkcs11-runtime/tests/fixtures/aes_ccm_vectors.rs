// SPDX-License-Identifier: MIT OR Apache-2.0
// NIST CAVP CCM-VNT, fixed Nlen=12 and Tlen=16 (byte lengths).
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
// Public known-answer keys, used only in isolated test stores.
pub struct Vector {
    pub key: &'static str,
    pub nonce: &'static str,
    pub aad: &'static str,
    pub plaintext: &'static str,
    pub ciphertext: &'static str,
}
pub const VECTORS: &[Vector] = &[
    // CCM-VNT128, Nlen=12, Tlen=16, Alen=32, Plen=24, Count=0.
    Vector {
        key: "005e8f4d8e0cbf4e1ceeb5d87a275848",
        nonce: "0ec3ac452b547b9062aac8fa",
        aad: "2f1821aa57e5278ffd33c17d46615b77363149dbc98470413f6543a6b749f2ca",
        plaintext: "b6f345204526439daf84998f380dcfb4b4167c959c04ff65",
        ciphertext: "9575e16f35da3c88a19c26a7b762044f4d7bbbafeff05d754829e2a7752fa3a14890972884b511d8",
    },
    // CCM-VNT192, Nlen=12, Tlen=16, Alen=32, Plen=24, Count=0.
    Vector {
        key: "d49b255aed8be1c02eb6d8ae2bac6dcd7901f1f61df3bbf5",
        nonce: "1af29e721c98e81fb6286370",
        aad: "64f8a0eee5487a4958a489ed35f1327e2096542c1bdb2134fb942ca91804c274",
        plaintext: "062eafb0cd09d26e65108c0f56fcc7a305f31c34e0f3a24c",
        ciphertext: "721344e2fd05d2ee50713531052d75e4071103ab0436f65f0af2a663da51bac626c9f4128ba5ec0b",
    },
    // CCM-VNT256, Nlen=12, Tlen=16, Alen=32, Plen=24, Count=0.
    Vector {
        key: "d6ff67379a2ead2ca87aa4f29536258f9fb9fc2e91b0ed18e7b9f5df332dd1dc",
        nonce: "2f1d0717a822e20c7cd28f0a",
        aad: "d50741d34c8564d92f396b97be782923ff3c855ea9757bde419f632c83997630",
        plaintext: "98626ffc6c44f13c964e7fcb7d16e988990d6d063d012d33",
        ciphertext: "50e22db70ac2bab6d6af7059c90d00fbf0fb52eee5eb650e08aca7dec636170f481dcb9fefb85c05",
    },
];
