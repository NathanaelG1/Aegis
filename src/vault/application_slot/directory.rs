//! Directory-relative I/O for the disposable application-slot fixture.
//!
//! The only ambient lookup opens `/`. Every subsequent lookup uses a held
//! directory descriptor, including after a parent is renamed. These checks do
//! not prevent a same-UID writer from racing mutations in the held namespace;
//! the synthetic caller still requires serialized access and trusted storage.

use crate::ErrorCode;
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags, Stat},
    io::Errno,
};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path},
};

const APPLICATION: &str = "application";
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(super) struct Directory {
    root: OwnedFd,
    application: OwnedFd,
    identity: (u64, u64),
}

impl Directory {
    /// The outer fixture bootstrap must already have created `root`.
    /// Only the fixed application child may be created here.
    pub(super) fn acquire(root: &Path, create: bool) -> Result<Self, ErrorCode> {
        if !root.is_absolute() {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let mut anchored = fs::open("/", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        for component in root.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    anchored = fs::openat(&anchored, name, DIRECTORY_FLAGS, Mode::empty())
                        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
                }
                _ => return Err(ErrorCode::PersistenceUnavailable),
            }
        }
        if create {
            match fs::mkdirat(&anchored, APPLICATION, Mode::RWXU) {
                Ok(()) => {
                    fs::fsync(&anchored).map_err(|_| ErrorCode::PersistenceUnavailable)?;
                }
                Err(Errno::EXIST) => {}
                Err(_) => return Err(ErrorCode::PersistenceUnavailable),
            }
        }
        let application = fs::openat(&anchored, APPLICATION, DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let metadata = fs::fstat(&application).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if !private_directory(&metadata) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let directory = Self {
            root: anchored,
            application,
            identity: object_identity(&metadata),
        };
        directory.check()?;
        Ok(directory)
    }

    pub(super) fn identity(&self) -> Result<(u64, u64), ErrorCode> {
        self.check()?;
        Ok(self.identity)
    }

    /// Check the fixed child in the held root, never the former ambient path.
    pub(super) fn check(&self) -> Result<(), ErrorCode> {
        let named = fs::statat(&self.root, APPLICATION, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        let held = fs::fstat(&self.application).map_err(|_| ErrorCode::ReconciliationRequired)?;
        if !private_directory(&named)
            || !private_directory(&held)
            || object_identity(&named) != self.identity
            || object_identity(&held) != self.identity
        {
            return Err(ErrorCode::ReconciliationRequired);
        }
        Ok(())
    }

    pub(super) fn create(&self, name: &str) -> Result<File, ErrorCode> {
        leaf(name)?;
        self.check()?;
        let file = fs::openat(
            &self.application,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(file_error)?;
        self.validate_file(name, &file)?;
        Ok(file)
    }

    pub(super) fn open(&self, name: &str, writable: bool) -> Result<File, ErrorCode> {
        self.open_optional(name, writable)?
            .ok_or(ErrorCode::PersistenceUnavailable)
    }

    pub(super) fn read_optional(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, ErrorCode> {
        let Some(file) = self.open_optional(name, false)? else {
            return Ok(None);
        };
        let metadata = fs::fstat(&file).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let length =
            usize::try_from(metadata.st_size).map_err(|_| ErrorCode::ReconciliationRequired)?;
        if length > limit {
            return Err(ErrorCode::ReconciliationRequired);
        }
        // Bound both the allocation and the read, including growth after fstat.
        let capacity = limit
            .checked_add(1)
            .ok_or(ErrorCode::PersistenceUnavailable)?;
        let read_limit = u64::try_from(capacity).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        (&file)
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if bytes.len() > limit {
            return Err(ErrorCode::ReconciliationRequired);
        }
        self.validate_file(name, &file)?;
        let after = fs::fstat(&file).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if usize::try_from(after.st_size).ok() != Some(bytes.len()) {
            return Err(ErrorCode::ReconciliationRequired);
        }
        Ok(Some(bytes))
    }

    pub(super) fn validate_file(&self, name: &str, file: &File) -> Result<(), ErrorCode> {
        leaf(name)?;
        self.check()?;
        let named = fs::statat(&self.application, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        let held = fs::fstat(file).map_err(|_| ErrorCode::ReconciliationRequired)?;
        if !private_file(&named)
            || !private_file(&held)
            || object_identity(&named) != object_identity(&held)
        {
            return Err(ErrorCode::ReconciliationRequired);
        }
        Ok(())
    }

    pub(super) fn sync(&self) -> Result<(), ErrorCode> {
        self.check()?;
        fs::fsync(&self.application).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        self.check()
    }

    /// Replacement and its following directory sync are separate journal steps.
    pub(super) fn replace(&self, stage: &str, slot: &str) -> Result<(), ErrorCode> {
        leaf(stage)?;
        leaf(slot)?;
        if stage == slot {
            return Err(ErrorCode::ReconciliationRequired);
        }
        let staged = self.open(stage, false)?;
        // Refuse to silently replace an observed alias or nonregular target.
        let target = self.open_optional(slot, false)?;
        self.validate_file(stage, &staged)?;
        if let Some(target) = &target {
            self.validate_file(slot, target)?;
        }
        self.check()?;
        fs::renameat(&self.application, stage, &self.application, slot)
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        self.validate_file(slot, &staged)
    }

    fn open_optional(&self, name: &str, writable: bool) -> Result<Option<File>, ErrorCode> {
        leaf(name)?;
        self.check()?;
        let named = match fs::statat(&self.application, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) if private_file(&metadata) => metadata,
            Ok(_) => return Err(ErrorCode::ReconciliationRequired),
            Err(Errno::NOENT) => {
                self.check()?;
                return Ok(None);
            }
            Err(error) => return Err(file_error(error)),
        };
        let access = if writable {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        };
        let opened = fs::openat(
            &self.application,
            name,
            access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let file = match opened {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => return Err(ErrorCode::ReconciliationRequired),
            Err(error) => return Err(file_error(error)),
        };
        self.validate_file(name, &file)?;
        let held = fs::fstat(&file).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if object_identity(&named) != object_identity(&held) {
            return Err(ErrorCode::ReconciliationRequired);
        }
        Ok(Some(file))
    }
}

fn leaf(name: &str) -> Result<(), ErrorCode> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(value)) if value == name)
        || components.next().is_some()
    {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(())
}

fn private_directory(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
        && metadata.st_uid == nix::unistd::geteuid().as_raw()
        && metadata.st_mode & 0o7077 == 0
}

fn private_file(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
        && metadata.st_nlink == 1
        && metadata.st_uid == nix::unistd::geteuid().as_raw()
        && metadata.st_mode & 0o7077 == 0
}

// Stat's dev/ino integer types vary between supported Unix compilation targets.
#[allow(clippy::unnecessary_cast)]
fn object_identity(metadata: &Stat) -> (u64, u64) {
    (metadata.st_dev as u64, metadata.st_ino as u64)
}

fn file_error(error: Errno) -> ErrorCode {
    match error {
        Errno::EXIST | Errno::LOOP | Errno::NOTDIR | Errno::ISDIR => {
            ErrorCode::ReconciliationRequired
        }
        _ => ErrorCode::PersistenceUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs as stdfs,
        io::Write,
        os::unix::fs::{symlink, DirBuilderExt},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "aegis-slot-directory-{}-{nonce}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            private_dir(&path);
            Self(path)
        }

        fn acquire(&self) -> Directory {
            Directory::acquire(&self.0, true).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = stdfs::remove_dir_all(&self.0);
        }
    }

    fn private_dir(path: &Path) {
        stdfs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }

    #[test]
    fn renamed_parent_does_not_redirect_reads_creation_or_replacement() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        private_dir(&parent);
        let root = parent.join("root");
        private_dir(&root);
        let directory = Directory::acquire(&root, true).unwrap();
        let identity = directory.identity().unwrap();
        directory.create("slot").unwrap().write_all(b"old").unwrap();

        let moved = fixture.0.join("moved");
        stdfs::rename(&parent, &moved).unwrap();
        private_dir(&parent);
        private_dir(&root);
        let decoy = Directory::acquire(&root, true).unwrap();
        decoy.create("slot").unwrap().write_all(b"decoy").unwrap();

        assert_eq!(directory.identity().unwrap(), identity);
        assert_eq!(directory.read_optional("slot", 8).unwrap().unwrap(), b"old");
        directory
            .create("stage")
            .unwrap()
            .write_all(b"new")
            .unwrap();
        directory.replace("stage", "slot").unwrap();
        directory.sync().unwrap();
        assert_eq!(
            stdfs::read(moved.join("root/application/slot")).unwrap(),
            b"new"
        );
        assert_eq!(decoy.read_optional("slot", 8).unwrap().unwrap(), b"decoy");
        assert!(!root.join("application/stage").exists());
    }

    #[test]
    fn replaced_application_child_requires_reconciliation() {
        let fixture = Fixture::new();
        let directory = fixture.acquire();
        stdfs::rename(fixture.0.join(APPLICATION), fixture.0.join("old")).unwrap();
        private_dir(&fixture.0.join(APPLICATION));
        assert_eq!(directory.check(), Err(ErrorCode::ReconciliationRequired));
        assert_eq!(
            directory.read_optional("missing", 8),
            Err(ErrorCode::ReconciliationRequired)
        );
        assert!(directory.create("stage").is_err());
        assert!(!fixture.0.join("old/stage").exists());
    }

    #[test]
    fn acquisition_rejects_symlink_non_directory_missing_and_relative_roots() {
        let fixture = Fixture::new();
        assert!(Directory::acquire(&fixture.0, false).is_err());
        assert!(!fixture.0.join(APPLICATION).exists());
        private_dir(&fixture.0.join("real"));
        symlink(fixture.0.join("real"), fixture.0.join("alias")).unwrap();
        assert!(Directory::acquire(&fixture.0.join("alias"), true).is_err());
        stdfs::write(fixture.0.join("file"), b"dummy").unwrap();
        assert!(Directory::acquire(&fixture.0.join("file/child"), true).is_err());
        assert!(Directory::acquire(&fixture.0.join("missing"), true).is_err());
        assert!(!fixture.0.join("missing").exists());
        assert!(Directory::acquire(Path::new("relative"), true).is_err());
        assert!(Directory::acquire(&fixture.0.join("real/../real"), true).is_err());
        symlink("real", fixture.0.join(APPLICATION)).unwrap();
        assert!(Directory::acquire(&fixture.0, true).is_err());
        assert!(Directory::acquire(&fixture.0, false).is_err());
        assert!(stdfs::read_dir(fixture.0.join("real"))
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn symlink_hardlink_directory_and_fifo_leaves_are_rejected() {
        let fixture = Fixture::new();
        let directory = fixture.acquire();
        let app = fixture.0.join(APPLICATION);
        directory
            .create("regular")
            .unwrap()
            .write_all(b"dummy")
            .unwrap();
        symlink("regular", app.join("symlink")).unwrap();
        symlink("absent", app.join("dangling")).unwrap();
        stdfs::hard_link(app.join("regular"), app.join("hardlink")).unwrap();
        private_dir(&app.join("directory"));
        fs::mknodat(
            &directory.application,
            "fifo",
            FileType::Fifo,
            Mode::RWXU,
            0,
        )
        .unwrap();
        for name in [
            "symlink",
            "dangling",
            "regular",
            "hardlink",
            "directory",
            "fifo",
        ] {
            assert!(directory.open(name, false).is_err(), "{name}");
            assert!(directory.open(name, true).is_err(), "{name}");
            assert!(directory.read_optional(name, 16).is_err(), "{name}");
        }
    }

    #[test]
    fn bounds_absence_exclusive_creation_and_object_validation_are_enforced() {
        let fixture = Fixture::new();
        let directory = fixture.acquire();
        assert_eq!(directory.read_optional("absent", 4).unwrap(), None);
        assert!(directory.open("absent", false).is_err());
        let mut original = directory.create("slot").unwrap();
        original.write_all(b"dummy").unwrap();
        assert!(directory.create("slot").is_err());
        assert_eq!(
            directory.read_optional("slot", 5).unwrap().unwrap(),
            b"dummy"
        );
        assert_eq!(
            directory.read_optional("slot", 4),
            Err(ErrorCode::ReconciliationRequired)
        );
        stdfs::rename(
            fixture.0.join("application/slot"),
            fixture.0.join("application/old"),
        )
        .unwrap();
        directory.create("slot").unwrap();
        assert_eq!(
            directory.validate_file("slot", &original),
            Err(ErrorCode::ReconciliationRequired)
        );
        for name in [
            "",
            ".",
            "..",
            "../escape",
            "slot/child",
            "/absolute",
            "slot/",
        ] {
            assert!(directory.create(name).is_err(), "{name}");
            assert!(directory.read_optional(name, 5).is_err(), "{name}");
        }
    }

    #[test]
    fn replacement_rejects_an_aliased_target_without_mutating_either_file() {
        let fixture = Fixture::new();
        let directory = fixture.acquire();
        let app = fixture.0.join(APPLICATION);
        directory
            .create("stage")
            .unwrap()
            .write_all(b"new")
            .unwrap();
        directory
            .create("target")
            .unwrap()
            .write_all(b"old")
            .unwrap();
        symlink("target", app.join("slot")).unwrap();
        assert_eq!(
            directory.replace("stage", "slot"),
            Err(ErrorCode::ReconciliationRequired)
        );
        assert_eq!(stdfs::read(app.join("target")).unwrap(), b"old");
        assert_eq!(stdfs::read(app.join("stage")).unwrap(), b"new");
        stdfs::remove_file(app.join("slot")).unwrap();
        stdfs::hard_link(app.join("target"), app.join("slot")).unwrap();
        assert_eq!(
            directory.replace("stage", "slot"),
            Err(ErrorCode::ReconciliationRequired)
        );
        assert_eq!(stdfs::read(app.join("target")).unwrap(), b"old");
        assert_eq!(stdfs::read(app.join("stage")).unwrap(), b"new");
    }
}
