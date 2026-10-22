use super::{Error, Snapshot};
use age::secrecy::ExposeSecret;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

const LIMIT: usize = 4 * 1024 * 1024;

pub(super) fn directory(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::Storage);
    }
    let uid = nix::unistd::Uid::current().as_raw();
    let mut part = PathBuf::new();
    for component in path.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(Error::Storage);
        }
        part.push(component);
        let m = fs::symlink_metadata(&part).map_err(|_| Error::Storage)?;
        if !m.is_dir()
            || (m.uid() != uid && m.uid() != 0)
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            return Err(Error::Storage);
        }
    }
    let m = fs::metadata(path).map_err(|_| Error::Storage)?;
    if m.uid() != uid || m.mode() & 0o777 != 0o700 {
        return Err(Error::Storage);
    }
    Ok(())
}

pub(crate) fn private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Storage)?;
    let m = file.metadata().map_err(|_| Error::Storage)?;
    if !m.is_file()
        || m.uid() != nix::unistd::Uid::current().as_raw()
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
    {
        return Err(Error::Storage);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if bytes.len() > limit {
        return Err(Error::Storage);
    }
    Ok(bytes)
}

pub(super) fn atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path.parent().ok_or(Error::Storage)?;
    directory(parent)?;
    let temporary = parent.join(format!(".write-{}", super::random()?));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| Error::Storage)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Storage)?;
        fs::rename(&temporary, path).map_err(|_| Error::Storage)?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(super) struct Store {
    pub(super) path: PathBuf,
}
impl Store {
    pub(super) fn initialize(path: &Path) -> Result<(), Error> {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| Error::Storage)?;
        directory(path)?;
        let identity = age::x25519::Identity::generate();
        atomic(
            &path.join("identity.key"),
            identity.to_string().expose_secret().as_bytes(),
        )?;
        atomic(&path.join("lock"), b"")?;
        Self { path: path.into() }.save(&Snapshot::default())
    }
    fn identity(&self) -> Result<age::x25519::Identity, Error> {
        let raw = private(&self.path.join("identity.key"), 256)?;
        std::str::from_utf8(&raw)
            .map_err(|_| Error::Storage)?
            .parse()
            .map_err(|_| Error::Storage)
    }
    pub(super) fn lock(&self) -> Result<File, Error> {
        directory(&self.path)?;
        // Check the inode actually opened, rather than following a link after lstat.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(self.path.join("lock"))
            .map_err(|_| Error::Storage)?;
        let m = file.metadata().map_err(|_| Error::Storage)?;
        if !m.is_file()
            || m.uid() != nix::unistd::Uid::current().as_raw()
            || m.mode() & 0o777 != 0o600
            || m.nlink() != 1
        {
            return Err(Error::Storage);
        }
        file.lock().map_err(|_| Error::Storage)?;
        Ok(file)
    }
    pub(super) fn load(&self) -> Result<Snapshot, Error> {
        let key = self.identity()?;
        let cipher = private(&self.path.join("vault.age"), LIMIT)?;
        let decryptor = age::Decryptor::new(cipher.as_slice()).map_err(|_| Error::Storage)?;
        if decryptor.is_scrypt() {
            return Err(Error::Storage);
        }
        let mut clear = Zeroizing::new(Vec::new());
        decryptor
            .decrypt(std::iter::once(&key as &dyn age::Identity))
            .map_err(|_| Error::Storage)?
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut clear)
            .map_err(|_| Error::Storage)?;
        if clear.len() > LIMIT {
            return Err(Error::Storage);
        }
        let snapshot: Snapshot = serde_json::from_slice(&clear).map_err(|_| Error::Storage)?;
        if snapshot.version != 1 {
            return Err(Error::Storage);
        }
        Ok(snapshot)
    }
    pub(super) fn save(&self, snapshot: &Snapshot) -> Result<(), Error> {
        let clear = Zeroizing::new(serde_json::to_vec(snapshot).map_err(|_| Error::Storage)?);
        if clear.len() > LIMIT - 4096 {
            return Err(Error::Capacity);
        }
        let recipient = self.identity()?.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|_| Error::Storage)?;
        let mut cipher = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut cipher)
            .map_err(|_| Error::Storage)?;
        writer.write_all(&clear).map_err(|_| Error::Storage)?;
        writer.finish().map_err(|_| Error::Storage)?;
        atomic(&self.path.join("vault.age"), &cipher)
    }
}
