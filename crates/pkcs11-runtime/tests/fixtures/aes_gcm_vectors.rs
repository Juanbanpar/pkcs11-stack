// SPDX-License-Identifier: MIT OR Apache-2.0
// NIST CAVP gcmEncryptExtIV{128,192,256}.rsp, IVlen=96, Taglen=128.
// https://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
// Public known-answer fixture keys; never use these values outside tests.
pub struct Vector {
    pub key: &'static str,
    pub nonce: &'static str,
    pub aad: &'static str,
    pub plaintext: &'static str,
    pub ciphertext: &'static str,
}
pub const VECTORS: &[Vector] = &[
    Vector {
        // AES-128, PTlen=0, AADlen=0, Count=0
        key: "11754cd72aec309bf52f7687212e8957",
        nonce: "3c819d9a9bed087615030b65",
        aad: "",
        plaintext: "",
        ciphertext: "250327c674aaf477aef2675748cf6971",
    },
    Vector {
        // AES-128, PTlen=0, AADlen=160, Count=0
        key: "2fb45e5b8f993a2bfebc4b15b533e0b4",
        nonce: "5b05755f984d2b90f94b8027",
        aad: "e85491b2202caf1d7dce03b97e09331c32473941",
        plaintext: "",
        ciphertext: "c75b7832b2a2d9bd827412b6ef5769db",
    },
    Vector {
        // AES-128, PTlen=128, AADlen=0, Count=0
        key: "7fddb57453c241d03efbed3ac44e371c",
        nonce: "ee283a3fc75575e33efd4887",
        aad: "",
        plaintext: "d5de42b461646c255c87bd2962d3b9a2",
        ciphertext: "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3",
    },
    Vector {
        // AES-128, PTlen=104, AADlen=160, Count=0
        key: "fe0121f42e599f88ff02a985403e19bb",
        nonce: "3bb9eb7724cbe1943d43de21",
        aad: "2662d895035b6519f3510eae0faa3900ad23cfdf",
        plaintext: "fd331ca8646091c29f21e5f0a1",
        ciphertext: "59fe29b07b0de8d869efbbd9b4d24c3e9c1c73c0af1097e26061c857de",
    },
    Vector {
        // AES-192, PTlen=0, AADlen=0, Count=0
        key: "aa740abfadcda779220d3b406c5d7ec09a77fe9d94104539",
        nonce: "ab2265b4c168955561f04315",
        aad: "",
        plaintext: "",
        ciphertext: "f149e2b5f0adaa9842ca5f45b768a8fc",
    },
    Vector {
        // AES-192, PTlen=0, AADlen=160, Count=0
        key: "093ef7551ebbff8eb0c0a8a4a62b198f0c2e838de10eeeee",
        nonce: "e656e93930ed5210ba3f0322",
        aad: "3da22dacfd11b21b0a713157f60aec0cd22f1add",
        plaintext: "",
        ciphertext: "1b2d2764573e20ae640bf29d48e5fe05",
    },
    Vector {
        // AES-192, PTlen=128, AADlen=0, Count=0
        key: "fbc0b4c56a714c83217b2d1bcadd2ed2e9efb0dcac6cc19f",
        nonce: "5f4b43e811da9c470d6a9b01",
        aad: "",
        plaintext: "d2ae38c4375954835d75b8e4c2f9bbb4",
        ciphertext: "69482957e6be5c54882d00314e0259cf191e9f29bef63a26860c1e020a21137e",
    },
    Vector {
        // AES-192, PTlen=104, AADlen=160, Count=0
        key: "4bea36ca9c7a5cf6df8f8bb5be1e97647d014bd181d50e28",
        nonce: "bff3d447b453eeb78f3a5650",
        aad: "33b7e18c7d5fd133faadd0ab524b86526e398203",
        plaintext: "d4f1053348696176de90c538c6",
        ciphertext: "0d9f7cde2614b71ed9c4b93503e88484488bd6470aa5e79b898c93dd28",
    },
    Vector {
        // AES-256, PTlen=0, AADlen=0, Count=0
        key: "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        nonce: "516c33929df5a3284ff463d7",
        aad: "",
        plaintext: "",
        ciphertext: "bdc1ac884d332457a1d2664f168c76f0",
    },
    Vector {
        // AES-256, PTlen=0, AADlen=160, Count=0
        key: "886cff5f3e6b8d0e1ad0a38fcdb26de97e8acbe79f6bed66959a598fa5047d65",
        nonce: "3a8efa1cd74bbab5448f9945",
        aad: "519fee519d25c7a304d6c6aa1897ee1eb8c59655",
        plaintext: "",
        ciphertext: "f6d47505ec96c98a42dc3ae719877b87",
    },
    Vector {
        // AES-256, PTlen=128, AADlen=0, Count=0
        key: "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
        nonce: "0d18e06c7c725ac9e362e1ce",
        aad: "",
        plaintext: "2db5168e932556f8089a0622981d017d",
        ciphertext: "fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489",
    },
    Vector {
        // AES-256, PTlen=104, AADlen=160, Count=0
        key: "69b458f2644af9020463b40ee503cdf083d693815e2659051ae0d039e606a970",
        nonce: "8d1da8ab5f91ccd09205944b",
        aad: "036ad5e5494ef817a8af2f5828784a4bfedd1653",
        plaintext: "f3e0e09224256bf21a83a5de8d",
        ciphertext: "c0a62d77e6031bfdc6b13ae217a794a9aaee48cd92e47761bf1baff0af",
    },
];
