// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{DigestAlgorithm, Error, SignRequest};
use cryptoki::mechanism::{Mechanism, rsa::PkcsPssParams};

pub(super) fn pkcs1_mechanism(digest: DigestAlgorithm, combined: bool) -> Mechanism<'static> {
    use DigestAlgorithm::*;
    if combined {
        match digest {
            Sha1 => Mechanism::Sha1RsaPkcs,
            Sha224 => Mechanism::Sha224RsaPkcs,
            Sha256 => Mechanism::Sha256RsaPkcs,
            Sha384 => Mechanism::Sha384RsaPkcs,
            Sha512 => Mechanism::Sha512RsaPkcs,
        }
    } else {
        Mechanism::RsaPkcs
    }
}

pub(super) fn pss_mechanism(
    request: &SignRequest<'_>,
    combined: bool,
) -> Result<Mechanism<'static>, Error> {
    use DigestAlgorithm::*;
    let pss = request
        .pss
        .ok_or(Error::InvalidParameters("PSS parameters required"))?;
    let params = PkcsPssParams {
        hash_alg: request.digest.mechanism(),
        mgf: pss.mgf_digest.mgf(),
        s_len: pss
            .salt_len
            .try_into()
            .map_err(|_| Error::InvalidParameters("PSS salt overflow"))?,
    };
    Ok(if combined {
        match request.digest {
            Sha1 => Mechanism::Sha1RsaPkcsPss(params),
            Sha224 => {
                return Err(Error::UnsupportedSigning(
                    "SHA-224 PSS combined mechanism unavailable",
                ));
            }
            Sha256 => Mechanism::Sha256RsaPkcsPss(params),
            Sha384 => Mechanism::Sha384RsaPkcsPss(params),
            Sha512 => Mechanism::Sha512RsaPkcsPss(params),
        }
    } else {
        Mechanism::RsaPkcsPss(params)
    })
}

pub(super) fn digest_info(digest: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    // DER DigestInfo with explicit NULL parameters. SHA-1 uses its original
    // 1.3.14.3.2.26 OID; SHA-2 uses the 2.16.840.1.101.3.4.2 arc.
    let oid = match digest {
        DigestAlgorithm::Sha1 => &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a][..],
        DigestAlgorithm::Sha224 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        ],
        DigestAlgorithm::Sha256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        DigestAlgorithm::Sha384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ],
        DigestAlgorithm::Sha512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
    };
    let algorithm_len = 2 + oid.len() + 2;
    let content_len = algorithm_len + 2 + data.len();
    let mut encoded = Vec::with_capacity(2 + content_len);
    encoded.extend_from_slice(&[0x30, content_len as u8]);
    encoded.extend_from_slice(&[0x30, (oid.len() + 2) as u8]);
    encoded.extend_from_slice(oid);
    encoded.extend_from_slice(&[0x05, 0x00, 0x04, data.len() as u8]);
    encoded.extend_from_slice(data);
    encoded
}

#[cfg(test)]
mod tests {
    use super::{DigestAlgorithm, digest_info};
    use sha1::{Digest, Sha1};

    #[test]
    fn digest_info_uses_standard_algorithm_identifiers() {
        let hash = Sha1::digest(b"message");
        let mut expected = vec![
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ];
        expected.extend_from_slice(&hash);
        assert_eq!(digest_info(DigestAlgorithm::Sha1, &hash), expected);

        for digest in [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let hash = digest.hash(b"message");
            let encoded = digest_info(digest, &hash);
            assert_eq!(encoded[0], 0x30);
            assert_eq!(encoded[1] as usize, encoded.len() - 2);
            assert_eq!(encoded.last(), hash.last());
        }
    }
}
