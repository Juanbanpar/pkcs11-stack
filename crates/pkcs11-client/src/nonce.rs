// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{AES_GCM_NONCE_LENGTH, Error, ObjectRef};
use fs2::FileExt;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"P11NSEQ1";
const HEADER_LEN: usize = MAGIC.len() + 32;
const RECORD_LEN: usize = 8 + 32;
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
        // Until initialization succeeds, any early return closes the locked file.
        sequence
            .file
            .write_all(MAGIC)
            .and_then(|()| sequence.file.write_all(&sequence.binding))
            .and_then(|()| sequence.append(0))
            .map_err(Error::NonceStateIo)?;
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(Error::NonceStateIo)?;
        }
        FileExt::unlock(&sequence.file).map_err(Error::NonceStateIo)?;
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
    fn record(&self, next: u64) -> [u8; RECORD_LEN] {
        let count = next.to_be_bytes();
        let digest = Sha256::new()
            .chain_update(self.binding)
            .chain_update(count)
            .finalize();
        let mut record = [0; RECORD_LEN];
        record[..count.len()].copy_from_slice(&count);
        record[count.len()..].copy_from_slice(&digest);
        record
    }
    fn append(&mut self, next: u64) -> std::io::Result<()> {
        let record = self.record(next);
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&record)?;
        self.file.sync_all()
    }
    fn next(&mut self, budget: u64) -> Result<u64, Error> {
        let length = self.file.metadata().map_err(Error::NonceStateIo)?.len();
        let header_len = HEADER_LEN as u64;
        let record_len = RECORD_LEN as u64;
        if length < header_len + record_len || (length - header_len) % record_len != 0 {
            return Err(Error::InvalidNonceState);
        }
        let mut header = [0; HEADER_LEN];
        self.file
            .rewind()
            .and_then(|()| self.file.read_exact(&mut header))
            .map_err(Error::NonceStateIo)?;
        if header.strip_prefix(MAGIC) != Some(self.binding.as_slice()) {
            return Err(Error::InvalidNonceState);
        }
        // The initial record holds zero. File length determines the last counter.
        let next = (length - header_len) / record_len - 1;
        let mut record = [0; RECORD_LEN];
        self.file
            .seek(SeekFrom::Start(length - record_len))
            .and_then(|_| self.file.read_exact(&mut record))
            .map_err(Error::NonceStateIo)?;
        if record != self.record(next) {
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
    pub fn reserve(&mut self, key: &ObjectRef) -> Result<[u8; AES_GCM_NONCE_LENGTH], Error> {
        self.reserve_with_budget(key, AES_GCM_NONCE_BUDGET)
    }
    fn reserve_with_budget(
        &mut self,
        key: &ObjectRef,
        budget: u64,
    ) -> Result<[u8; AES_GCM_NONCE_LENGTH], Error> {
        if selector_binding(key) != self.binding {
            return Err(Error::InvalidNonceState);
        }
        self.file.try_lock_exclusive().map_err(|error| {
            // Windows lock contention is not classified as std WouldBlock.
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
                Error::NonceStateBusy
            } else {
                Error::NonceStateIo(error)
            }
        })?;
        let result = self.next(budget).and_then(|next| {
            self.append(next + 1).map_err(Error::NonceStateIo)?;
            let mut nonce = [0; AES_GCM_NONCE_LENGTH];
            nonce[4..].copy_from_slice(&next.to_be_bytes());
            Ok(nonce)
        });
        FileExt::unlock(&self.file).map_err(Error::NonceStateIo)?;
        result
    }
}

fn selector_binding(key: &ObjectRef) -> [u8; 32] {
    Sha256::digest(key.uri().to_secret_uri().expose_secret().as_bytes()).into()
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
                    .args(["--exact", "nonce::tests::process_writer", "--nocapture"])
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
