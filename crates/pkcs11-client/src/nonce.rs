// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ObjectRef, envelope::selector_binding};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"P11NSEQ1";
const HEADER: u64 = 40;
const RECORD: u64 = 40;
/// Maximum reservations per nonce state/key lifetime, including failed encryptions.
pub const AES_GCM_NONCE_BUDGET: u64 = 1 << 32;

/// Durable single-host nonce journal for one new key and canonical selector.
///
/// All writers of the actual key must share this file on a trusted local filesystem.
/// Never reset, copy or restore the state while retaining the key. Renamed selectors,
/// copied keys, uncoordinated hosts and malicious directory owners are outside this
/// contract. Missing state or an invalid header/tail fails closed; retire the key
/// if state is lost. Historical record contents are not scanned during allocation.
/// File locks coordinate processes; reservations are flushed before encryption.
#[derive(Debug)]
pub struct NonceSequence {
    file: File,
    binding: [u8; 32],
}
impl NonceSequence {
    /// Exclusively create state for a new, previously unused key. Never overwrites.
    /// The caller must establish that no other allocator/raw encryption used the key.
    /// A failed initialization can leave an unusable file; do not silently reset it.
    pub fn create(path: impl AsRef<Path>, key: &ObjectRef) -> Result<Self, Error> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(Error::NonceStateIo)?;
        let mut sequence = Self {
            file,
            binding: selector_binding(key),
        };
        sequence
            .file
            .try_lock_exclusive()
            .map_err(Error::NonceStateIo)?;
        let result = (|| {
            sequence.file.write_all(MAGIC)?;
            sequence.file.write_all(&sequence.binding)?;
            sequence.append(0)?;
            #[cfg(unix)]
            {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                File::open(parent)?.sync_all()?;
            }
            Ok::<_, std::io::Error>(())
        })();
        let unlock = FileExt::unlock(&sequence.file);
        result.map_err(Error::NonceStateIo)?;
        unlock.map_err(Error::NonceStateIo)?;
        Ok(sequence)
    }
    /// Open existing state. Opening never creates or repairs a missing/corrupt journal.
    pub fn open(path: impl AsRef<Path>, key: &ObjectRef) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(Error::NonceStateIo)?;
        if !file.metadata().map_err(Error::NonceStateIo)?.is_file() {
            return Err(Error::InvalidNonceState);
        }
        Ok(Self {
            file,
            binding: selector_binding(key),
        })
    }
    fn append(&mut self, next: u64) -> std::io::Result<()> {
        let count = next.to_be_bytes();
        let digest = Sha256::digest([self.binding.as_slice(), count.as_slice()].concat());
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&count)?;
        self.file.write_all(&digest)?;
        self.file.sync_all()
    }
    fn next(&mut self, budget: u64) -> Result<u64, Error> {
        let length = self.file.metadata().map_err(Error::NonceStateIo)?.len();
        if length < HEADER + RECORD || (length - HEADER) % RECORD != 0 {
            return Err(Error::InvalidNonceState);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(Error::NonceStateIo)?;
        let mut header = [0; 40];
        self.file
            .read_exact(&mut header)
            .map_err(Error::NonceStateIo)?;
        if &header[..8] != MAGIC || header[8..] != self.binding {
            return Err(Error::InvalidNonceState);
        }
        self.file
            .seek(SeekFrom::Start(length - RECORD))
            .map_err(Error::NonceStateIo)?;
        let mut count = [0; 8];
        let mut checksum = [0; 32];
        self.file
            .read_exact(&mut count)
            .map_err(Error::NonceStateIo)?;
        self.file
            .read_exact(&mut checksum)
            .map_err(Error::NonceStateIo)?;
        let expected: [u8; 32] =
            Sha256::digest([self.binding.as_slice(), count.as_slice()].concat()).into();
        let next = u64::from_be_bytes(count);
        if checksum != expected || next != (length - HEADER) / RECORD - 1 {
            return Err(Error::InvalidNonceState);
        }
        if next >= budget {
            return Err(Error::NonceBudgetExhausted);
        }
        Ok(next)
    }
    /// Persist one reservation before returning it. Provider/output failures do not
    /// roll it back. A busy lock, malformed state, exhausted budget or I/O error
    /// returns no nonce; no cryptographic operation has started in this method.
    pub fn reserve(&mut self, key: &ObjectRef) -> Result<[u8; 12], Error> {
        self.reserve_with_budget(key, AES_GCM_NONCE_BUDGET)
    }
    fn reserve_with_budget(&mut self, key: &ObjectRef, budget: u64) -> Result<[u8; 12], Error> {
        if selector_binding(key) != self.binding {
            return Err(Error::InvalidNonceState);
        }
        self.file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                Error::NonceStateBusy
            } else {
                Error::NonceStateIo(error)
            }
        })?;
        let result = (|| {
            let next = self.next(budget)?;
            self.append(next + 1).map_err(Error::NonceStateIo)?;
            u128::from(next).to_be_bytes()[4..]
                .try_into()
                .map_err(|_| Error::InvalidNonceState)
        })();
        let unlocked = FileExt::unlock(&self.file).map_err(Error::NonceStateIo);
        unlocked?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Store(std::path::PathBuf);
    impl Store {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pkcs11-nonce-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("state")
        }
    }
    impl Drop for Store {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn key() -> ObjectRef {
        ObjectRef::new(
            "pkcs11:token=disposable;id=%01;type=secret-key"
                .parse()
                .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn reservations_survive_restart_and_exhaustion() {
        let store = Store::new();
        let mut first = NonceSequence::create(store.path(), &key()).unwrap();
        assert_eq!(first.reserve_with_budget(&key(), 2).unwrap(), [0; 12]);
        drop(first);
        let mut second = NonceSequence::open(store.path(), &key()).unwrap();
        assert_eq!(second.reserve_with_budget(&key(), 2).unwrap()[11], 1);
        assert!(matches!(
            second.reserve_with_budget(&key(), 2),
            Err(Error::NonceBudgetExhausted)
        ));
        drop(second);
        assert!(matches!(
            NonceSequence::open(store.path(), &key())
                .unwrap()
                .reserve_with_budget(&key(), 2),
            Err(Error::NonceBudgetExhausted)
        ));
    }
    #[test]
    fn missing_existing_mismatched_busy_and_read_only_state_fail_closed() {
        let store = Store::new();
        assert!(NonceSequence::open(store.path(), &key()).is_err());
        let first = NonceSequence::create(store.path(), &key()).unwrap();
        let before = std::fs::read(store.path()).unwrap();
        assert!(NonceSequence::create(store.path(), &key()).is_err());
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        let other =
            ObjectRef::new("pkcs11:token=other;id=%01;type=secret-key".parse().unwrap()).unwrap();
        assert!(matches!(
            NonceSequence::open(store.path(), &other)
                .unwrap()
                .reserve(&other),
            Err(Error::InvalidNonceState)
        ));
        let mut second = NonceSequence::open(store.path(), &key()).unwrap();
        first.file.try_lock_exclusive().unwrap();
        assert!(matches!(second.reserve(&key()), Err(Error::NonceStateBusy)));
        FileExt::unlock(&first.file).unwrap();
        second.file = File::open(store.path()).unwrap();
        assert!(second.reserve(&key()).is_err());
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
    }
    #[test]
    fn truncated_and_corrupt_journals_never_allocate() {
        let store = Store::new();
        drop(NonceSequence::create(store.path(), &key()).unwrap());
        let original = std::fs::read(store.path()).unwrap();
        for length in [0, 8, 39, 40, 79, 81] {
            let mut damaged = original.clone();
            damaged.resize(length, 0);
            std::fs::write(store.path(), &damaged).unwrap();
            assert!(
                NonceSequence::open(store.path(), &key())
                    .unwrap()
                    .reserve(&key())
                    .is_err()
            );
            assert_eq!(std::fs::read(store.path()).unwrap(), damaged);
        }
        for index in [0, 8, 40, 48, 79] {
            let mut damaged = original.clone();
            damaged[index] ^= 1;
            std::fs::write(store.path(), &damaged).unwrap();
            assert!(
                NonceSequence::open(store.path(), &key())
                    .unwrap()
                    .reserve(&key())
                    .is_err()
            );
        }
    }
    #[test]
    fn process_writer() {
        let Some(path) = std::env::var_os("PKCS11_NONCE_TEST_STATE") else {
            return;
        };
        let mut state = NonceSequence::open(&path, &key()).unwrap();
        for _ in 0..5 {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match state.reserve(&key()) {
                    Ok(_) => break,
                    Err(Error::NonceStateBusy) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(2))
                    }
                    result => panic!("reservation failed: {result:?}"),
                }
            }
        }
    }
    #[test]
    fn independent_processes_share_one_monotonic_sequence() {
        let store = Store::new();
        drop(NonceSequence::create(store.path(), &key()).unwrap());
        let mut children: Vec<_> = (0..8)
            .map(|_| {
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "nonce::tests::process_writer"])
                    .env("PKCS11_NONCE_TEST_STATE", store.path())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for child in &mut children {
            assert!(child.wait().unwrap().success());
        }
        let mut state = NonceSequence::open(store.path(), &key()).unwrap();
        assert_eq!(state.reserve(&key()).unwrap()[11], 40);
        let journal = std::fs::read(store.path()).unwrap();
        for (counter, record) in journal[40..].chunks_exact(40).enumerate() {
            assert_eq!(&record[..8], &(counter as u64).to_be_bytes());
        }
    }
}
