# Retired cryptoki override

The workspace now requires released **cryptoki 0.12.1 or newer in the 0.12 line**.
The Cargo override and `cryptoki-0.12.0` source copy were removed on 2026-09-25.
The lockfile selects 0.12.1, with registry checksum
`625cf4599c43d69a16996ce2573fc80745a0b0300c962f0bfa11d55b6cab2b2d`.

Version 0.12.1 decodes CKA_ALLOWED_MECHANISMS using bounded native-endian chunks,
rejecting partial elements without alignment assumptions. This replaces our local
fix for the byte-count/element-count out-of-bounds read. See the
[released source](https://docs.rs/crate/cryptoki/0.12.1/source/src/object.rs),
[upstream fix](https://github.com/parallaxsecond/rust-cryptoki/pull/368) and
[advisory](https://rustsec.org/advisories/RUSTSEC-2026-0286.html).

The runtime SoftHSM suite checks actual empty, single and multiple mechanism lists,
permitted signing and rejection of mechanisms outside those restrictions. The old
vendored-only decoder test command is no longer applicable. Run:

```sh
cargo test --workspace --locked
./tools/test-softhsm.sh
```

## Historical provenance

The removed source was the published cryptoki 0.12.0 archive, SHA-256
`ff765b99fc49f3116c9a908484486a2b92fd73c48da45c3a69716471c6cc56c6`, upstream revision
`bf51837c01c57bb39aa95432482b747449179b24` in
[parallaxsecond/rust-cryptoki](https://github.com/parallaxsecond/rust-cryptoki).
Only `src/object.rs` was modified locally. The [Stage 4 report](../docs/stage-4-report.md)
records the discovery and original validation. Third-party source remains Apache-2.0;
original project code and this provenance document remain MIT OR Apache-2.0.
