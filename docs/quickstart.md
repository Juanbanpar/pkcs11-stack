# Quickstart with disposable SoftHSM

Sign a message with a software token using `pkcs11ctl`, then use the same key
from Rust. This walkthrough uses a fresh SoftHSM store on Linux. Results from
this store establish software-provider behavior only. Physical HSM compatibility
and cryptographic certification require separate evidence.

## Install the tools

Use Rust 1.88 or newer with Cargo and a native linker. The walkthrough was
tested on Ubuntu 24.04 (x86-64) with SoftHSM 2.6.1. Install the packages below.
OpenSC supplies `pkcs11-tool` for checking the provider's slots.

```sh
sudo apt-get update
sudo apt-get install build-essential softhsm2 opensc
```

Run the remaining commands from the repository root in the same shell. Build
the CLI from the checkout before the initial release.

```sh
cargo build -p pkcs11ctl --locked
cli="${CARGO_TARGET_DIR:-target}/debug/pkcs11ctl"
"$cli" --help
```

After publication, you can use [the crates.io installation](../crates/pkcs11ctl/README.md#installation)
for the CLI steps. Set `cli=pkcs11ctl` to use that executable. The Rust example
below runs from the checkout.

## Create an isolated token

Start a dedicated Bash shell so the environment and cleanup stay scoped to
this walkthrough.

```sh
bash
```

```sh
set -euo pipefail
umask 077

demo=$(mktemp -d /tmp/pkcs11-stack-demo.XXXXXXXX)
trap 'rm -rf -- "$demo"' EXIT
mkdir "$demo/tokens"
export SOFTHSM2_CONF="$demo/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' \
  "$demo/tokens" > "$SOFTHSM2_CONF"

# Re-establish the CLI path in this shell. Use cli=pkcs11ctl for an installed CLI.
cli="${CARGO_TARGET_DIR:-target}/debug/pkcs11ctl"
module=
for candidate in /usr/lib/softhsm/libsofthsm2.so \
                 /usr/lib/*-linux-gnu/softhsm/libsofthsm2.so \
                 /usr/lib64/pkcs11/libsofthsm2.so; do
  if [ -f "$candidate" ]; then
    module=$candidate
    break
  fi
done
if [ -z "$module" ]; then
  printf '%s\n' 'SoftHSM module not found. Check the installed libsofthsm2 package.' >&2
  exit 1
fi

printf 'Config: %s\nModule: %s\n' "$SOFTHSM2_CONF" "$module"
test "$SOFTHSM2_CONF" = "$demo/softhsm2.conf"
grep -Fx "directories.tokendir = $demo/tokens" "$SOFTHSM2_CONF"
test -z "$(ls -A -- "$demo/tokens")"
softhsm2-util --module "$module" --show-slots
```

The config must point to the new directory and the slot listing must show
an uninitialized token before proceeding. Use the packaged SoftHSM library.
The SO PIN initializes or administers the token. The USER PIN authorizes
key generation and signing. The values below are public demonstration PINs
for the disposable store. Production applications should obtain credentials
from their secret source and keep real PINs out of shell arguments and logs.

```sh
softhsm2-util --module "$module" --init-token --free \
  --label pkcs11-stack-demo --so-pin 87654321 --pin 12345678
printf '%s\n' 12345678 > "$demo/user.pin"
pkcs11-tool --module "$module" --list-slots
"$cli" --module "$module" tokens
```

Find the initialized token labeled `pkcs11-stack-demo`. SoftHSM may also
report an uninitialized slot. The fresh store makes the label unique for
this walkthrough. In a shared store, use the token serial and object ID.

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

Look for RSA key generation and SHA-256 with RSA PKCS#1 v1.5 in the mechanism
listing. The pair shares binary ID `01`, written as `%01` in each URI. Verification
should report `verified: true` and `verification: "token"`. Signing creates a new
256-byte signature file for the 2048-bit RSA key.

If signing reports no matching object, check the label and ID and confirm
the CLI can log in as USER. If an output file exists, choose a new path.
If generation failed, inspect the token before rerunning. The provider may
have created an object before reporting an error.

## Sign from Rust with the same key

Run the [client signing example](../crates/pkcs11-client/examples/sign.rs).

```sh
cargo run --locked --quiet -p pkcs11-client --example sign -- \
  "$module" "$private_key" "$demo/user.pin" "$demo/message.txt" > "$demo/rust.sig"

"$cli" --module "$module" verify --key "$public_key" \
  --algorithm rsa-pkcs1 --digest sha256 --input "$demo/message.txt" \
  --signature "$demo/rust.sig"
```

The example loads the module with `Provider::load`, derives the token selector
from the private-key URI, and creates a one-session read-only client. It reads
the PIN into protected storage, resolves a private-key reference, and signs
with the default policy. It checks client closure and provider finalization
before writing the signature. Verification should again report `verified: true`.

For dependency setup and certificate binding, see the
[client guide](../crates/pkcs11-client/README.md). For other workflows, see the
[runnable examples](examples.md) and [troubleshooting guide](troubleshooting.md).

## Clean up

Exit the dedicated Bash shell. Its exit trap deletes only the temporary store
and the PIN and signature files created for this walkthrough.

```sh
exit
```
