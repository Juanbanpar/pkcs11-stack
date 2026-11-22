# Quickstart with disposable SoftHSM

Sign and verify a message with `pkcs11ctl`, then sign with the same key from
Rust. Use a disposable software token. This walkthrough does not qualify
physical devices or establish cryptographic certification.

## Install the tools

Use Rust 1.88 or newer with Cargo and a native linker. The walkthrough was
tested on Ubuntu 24.04 (x86-64) with SoftHSM 2.6.1. Install the packages below.
OpenSC supplies `pkcs11-tool` for checking the provider's slots.

```sh
sudo apt-get update
sudo apt-get install build-essential softhsm2 opensc
```

Install the CLI, then open a dedicated Bash shell for the remaining commands.

```sh
cargo install pkcs11ctl --version 0.1.1 --locked
bash
```

```sh
cli=pkcs11ctl
"$cli" --help
```

If building from source, use the [CLI checkout instructions](../crates/pkcs11ctl/README.md#from-a-checkout)
and set `cli` to the absolute path of the resulting `pkcs11ctl` binary.

## Create an isolated token

Use Ubuntu's packaged SoftHSM library at the path below. On other
distributions, use the absolute path from the trusted package's file list.

```sh
set -euo pipefail
umask 077

module=/usr/lib/softhsm/libsofthsm2.so
test -r "$module"
demo=$(mktemp -d /tmp/pkcs11-stack-demo.XXXXXXXX)
trap 'rm -rf -- "$demo"' EXIT
mkdir "$demo/tokens"
export SOFTHSM2_CONF="$demo/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' \
  "$demo/tokens" > "$SOFTHSM2_CONF"
softhsm2-util --module "$module" --show-slots
```

The slot listing should show an uninitialized token. The SO PIN is for token
administration. The USER PIN authorizes key generation and signing.
The values below are public credentials for this disposable store. Keep
production PINs out of arguments and logs.

```sh
test "$SOFTHSM2_CONF" = "$demo/softhsm2.conf"
grep -Fqx "directories.tokendir = $demo/tokens" "$SOFTHSM2_CONF"
test -z "$(ls -A -- "$demo/tokens")"
softhsm2-util --module "$module" --init-token --free \
  --label pkcs11-stack-demo --so-pin 87654321 --pin 12345678
printf '%s\n' 12345678 > "$demo/user.pin"
pkcs11-tool --module "$module" --list-slots
"$cli" --module "$module" tokens
```

Look for the initialized `pkcs11-stack-demo` token. Its label is unique in this
store. Use a token serial and object ID when selecting in a shared store.

## Generate, sign, and verify

```sh
token='pkcs11:token=pkcs11-stack-demo'
private_key="$token;id=%01;type=private"
public_key="$token;id=%01;type=public"

"$cli" --module "$module" mechanisms --token "$token" > "$demo/mechanisms.txt"
grep -E 'CKM_(RSA_PKCS_KEY_PAIR_GEN|SHA256_RSA_PKCS)"' "$demo/mechanisms.txt"
"$cli" --module "$module" generate --token "$token" \
  --kind rsa --bits 2048 --label demo-signing --id 01 \
  --pin-file "$demo/user.pin" --confirm

printf '%s\n' 'Hello from pkcs11-stack' > "$demo/message.txt"
"$cli" --module "$module" sign --key "$private_key" \
  --algorithm rsa-pkcs1 --digest sha256 --input "$demo/message.txt" \
  --output "$demo/cli.sig" --pin-file "$demo/user.pin"

"$cli" --module "$module" verify --key "$public_key" \
  --algorithm rsa-pkcs1 --digest sha256 --input "$demo/message.txt" \
  --signature "$demo/cli.sig"
test "$(wc -c < "$demo/cli.sig")" -eq 256
```

The key pair shares binary ID `01`, written as `%01` in each URI. Verify
reports `verified: true` and `verification: "token"`. Use a fresh output path
if a signature file already exists. If generation failed, inspect the token
before trying again because the provider may already have created an object.

## Sign from Rust with the same key

From a checkout of `v0.1.1`, run the
[client signing example](../crates/pkcs11-client/examples/sign.rs) in the same shell.

```sh
cargo run --locked --quiet -p pkcs11-client --example sign -- \
  "$module" "$private_key" "$demo/user.pin" "$demo/message.txt" > "$demo/rust.sig"

"$cli" --module "$module" verify --key "$public_key" \
  --algorithm rsa-pkcs1 --digest sha256 --input "$demo/message.txt" \
  --signature "$demo/rust.sig"
```

The example loads the trusted module, selects the token and key by URI, and
authenticates with the PIN file. It checks client closure and module finalization
before writing the signature. Verification should again report `verified: true`.

See the [client guide](../crates/pkcs11-client/README.md) for other workflows and
[troubleshooting](troubleshooting.md) if a step fails.

## Clean up

Exit the dedicated Bash shell. Its exit trap deletes only the temporary store
and the PIN and signature files created for this walkthrough.

```sh
exit
```
