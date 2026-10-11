# Platform validation policy

Linux x86_64 is the current locally validated platform. The workspace requires Rust
1.85 or newer and a system linker. Support claims distinguish building/pure tests
from successful use of a particular PKCS#11 provider.

| Platform | CI coverage | Provider acceptance |
| --- | --- | --- |
| Linux x86_64 (`ubuntu-latest`) | Workspace and individual crates; stable and Rust 1.85; production adapter features; property tests; bounded ASan fuzzing | Packaged and pinned upstream SoftHSM, including application examples |
| Windows (`windows-2022`) | Stable workspace/all-target builds, pure tests, doctests and adapter feature configurations | None configured |
| macOS (`macos-14`) | Stable workspace/all-target builds, pure tests, doctests and adapter feature configurations | None configured |

The Windows/macOS jobs are portability gates added by this revision. They have not
been executed in the local Linux environment; their native CI results must be
checked before claiming those platforms validated. Vendor modules, protected-path
authentication and hardware behavior require separate acceptance on each deployment
platform. Other operating systems and architectures currently have no CI commitment.

The pure suite uses platform-native absolute paths when testing `module-path`.
POSIX paths must not be assumed absolute on Windows. Failed property tests retain
their seed/minimized case for reproduction. CI uses property seed 20260927 and a
second seed, 20260928, in the MSRV job. Local runs remain random unless an explicit
seed is supplied.

Promote a platform's support claim only after its native build/tests pass, and
describe provider validation separately. A Linux cross-build or an ignored hardware
test does not establish that a provider operates correctly on another platform.
