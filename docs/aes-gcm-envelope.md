# AES-GCM envelope

The CLI and desktop use this format by default. The selected token key determines
the AES key size. Keep any additional authenticated data (AAD) separately and
supply the same bytes when decrypting.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 6 | ASCII `P11GCM` |
| 6 | 1 | Version `0x01` |
| 7 | 12 | Nonce |
| 19 | 0–16,777,216 | Ciphertext |
| End − 16 | 16 | Authentication tag |

A version 1 envelope is 35 to 16,777,251 bytes. The implementation accepts up to
1 MiB of AAD and releases plaintext only after authentication succeeds.

## Nonce state

- Initialize state only for a new, unused key. Use the same key selector and one
  state file for every encryption with that key.
- Keep the file on a trusted local filesystem with working file locks and durable
  writes. Never copy, reset, or restore it while keeping the key. If state is lost
  or its history is uncertain, retire the key for encryption.
- Use explicit nonces with an external allocator if the key is shared across hosts
  or used by applications outside the journal. The journal binds to the selector
  and cannot detect which other selectors or copies hold the same key.

Each reservation locks the file, checks the header and last record, appends
the next counter, and flushes it before encryption. Failed operations still
consume their reservation. A busy lock or invalid journal stops encryption.
Each reservation adds 40 bytes. The limit is 2³² reservations per key.

## Nonce journal format

Integers are big-endian. The header holds eight bytes of ASCII `P11NSEQ1`
followed by the 32-byte SHA-256 digest of the canonical object URI. Each record
holds the next counter as an eight-byte integer and a 32-byte SHA-256 checksum
of the URI digest followed by the encoded counter.

The first record contains zero. A reservation writes the incremented counter
and uses the previous counter as the nonce, padded with four zero bytes on the
left. The last counter must equal the number of records minus one. The checks
detect incomplete writes and accidental damage to the header or last record.
Protect the journal directory from writes by other users and from rollback.
