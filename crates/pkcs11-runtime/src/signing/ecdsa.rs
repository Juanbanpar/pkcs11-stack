// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DigestAlgorithm;
use cryptoki::mechanism::Mechanism;

pub(super) fn mechanism(digest: DigestAlgorithm, combined: bool) -> Mechanism<'static> {
    use DigestAlgorithm::*;
    if combined {
        match digest {
            Sha1 => Mechanism::EcdsaSha1,
            Sha224 => Mechanism::EcdsaSha224,
            Sha256 => Mechanism::EcdsaSha256,
            Sha384 => Mechanism::EcdsaSha384,
            Sha512 => Mechanism::EcdsaSha512,
        }
    } else {
        Mechanism::Ecdsa
    }
}
