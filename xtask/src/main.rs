//! Native release tooling. Uses the OS tar command (bsdtar on Windows).
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn run(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn copy(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy(&entry.path(), &target.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), target.join(entry.file_name()))?;
        }
    }
    Ok(())
}
fn checksum(bytes: &[u8], name: &str) -> Vec<u8> {
    format!("{:x}  {name}\n", Sha256::digest(bytes)).into_bytes()
}
fn package(root: &Path, tag: &str, target: &str) -> Result<()> {
    if tag.is_empty()
        || !tag.as_bytes()[0].is_ascii_alphanumeric()
        || tag.len() > 128
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("invalid release tag".into());
    }
    let windows = target == "x86_64-pc-windows-msvc";
    if ![
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ]
    .contains(&target)
    {
        return Err("unsupported target".into());
    }
    let binary = if windows { "aegis.exe" } else { "aegis" };
    let name = format!("aegis-{tag}-{target}");
    let dist = root.join("dist");
    fs::create_dir_all(&dist)?;
    let work = dist.join(format!(".package-{}", std::process::id()));
    fs::create_dir(&work)?;
    let result = (|| {
        let staging = work.join(&name);
        fs::create_dir(&staging)?;
        let source = root
            .join("target")
            .join(target)
            .join("release")
            .join(binary);
        fs::copy(source, staging.join(binary))?;
        for file in [
            "README.md",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "SECURITY.md",
            "install.sh",
        ] {
            fs::copy(root.join(file), staging.join(file))?;
        }
        copy(&root.join("docs"), &staging.join("docs"))?;
        let metadata: Value = serde_json::from_str(&run(Command::new("cargo")
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .current_dir(root))?)?;
        let version = metadata["packages"]
            .as_array()
            .ok_or("missing packages")?
            .iter()
            .find(|p| p["name"] == "aegis-broker")
            .ok_or("missing crate")?["version"]
            .as_str()
            .ok_or("missing version")?;
        let release = json!({"tag":tag, "package_version":version, "target":target,
            "features":if windows { vec![] } else { vec!["proxy"] },
            "commit":run(Command::new("git").args(["rev-parse", "HEAD"]).current_dir(root))?.trim(),
            "source_dirty":!run(Command::new("git").args(["status", "--porcelain"]).current_dir(root))?.is_empty(),
            "rustc":run(Command::new("rustc").arg("--version"))?.trim(),
            "binary_sha256":format!("{:x}", Sha256::digest(fs::read(staging.join(binary))?)), "distribution_signed":false});
        fs::write(
            staging.join("release.json"),
            serde_json::to_vec_pretty(&release)?,
        )?;
        fs::write(staging.join("INSTALL.md"), "Run ./aegis --help (Windows: .\\aegis.exe --help). See docs/releases.md and docs/secret-proxy.md. Native executable; no language runtime required.\n")?;
        let archive_name = format!("{name}{}", if windows { ".zip" } else { ".tar.gz" });
        let archive = dist.join(&archive_name);
        // Git Bash can put GNU tar ahead of Windows' ZIP-capable bsdtar.
        let tar = if windows {
            PathBuf::from(std::env::var_os("SystemRoot").ok_or("missing Windows system root")?)
                .join("System32")
                .join("tar.exe")
        } else {
            PathBuf::from("tar")
        };
        run(Command::new(&tar)
            .arg("-a")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&work)
            .arg(&name))?;
        let bytes = fs::read(&archive)?;
        let signature: &[u8] = if windows { b"PK\x03\x04" } else { b"\x1f\x8b" };
        if !bytes.starts_with(signature) {
            return Err("archive format does not match extension".into());
        }
        let extraction = work.join("extracted");
        fs::create_dir(&extraction)?;
        run(Command::new(&tar)
            .arg("-xf")
            .arg(&archive)
            .arg("-C")
            .arg(&extraction))?;
        let extracted = extraction.join(&name).join(binary);
        if fs::read(&extracted)? != fs::read(staging.join(binary))? {
            return Err("archive binary mismatch".into());
        }
        let empty = work.join("empty");
        fs::create_dir(&empty)?;
        let smoke = |args: &[&str]| -> Result<String> {
            let mut command = Command::new(&extracted);
            command.args(args).current_dir(&empty).env_clear();
            for key in ["SystemRoot", "WINDIR"] {
                if let Ok(v) = std::env::var(key) {
                    command.env(key, v);
                }
            }
            run(&mut command)
        };
        if !smoke(&["--version"])?.contains(version)
            || !smoke(&["demo"])?.contains("provider dispatches=1 remaining_uses=19")
        {
            return Err("smoke test failed".into());
        }
        if smoke(&["--help"])?.contains("proxy --state-dir") == windows {
            return Err("unexpected platform capabilities".into());
        }
        let mut command = Command::new(&extracted);
        command
            .arg("synthetic-agent")
            .current_dir(&empty)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in ["SystemRoot", "WINDIR"] {
            if let Ok(value) = std::env::var(key) {
                command.env(key, value);
            }
        }
        let mut child = command.spawn()?;
        child
            .stdin
            .take()
            .ok_or("missing stdin")?
            .write_all(b"{\"version\":1,\"action\":{\"method\":\"discover_operations\"}}\n")?;
        let output = child.wait_with_output()?;
        let discovery: Value = serde_json::from_slice(&output.stdout)?;
        if !output.status.success()
            || !discovery["error"].is_null()
            || discovery["result"].is_null()
        {
            return Err("extracted JSON-lines discovery failed".into());
        }
        if fs::read_dir(&empty)?.next().is_some() {
            return Err("smoke test wrote working files".into());
        }
        fs::write(
            dist.join(format!("{archive_name}.sha256")),
            checksum(&fs::read(&archive)?, &archive_name),
        )?;
        println!("Packaged and verified {archive_name}");
        Ok(())
    })();
    let _ = fs::remove_dir_all(work);
    result
}
fn inventory(root: &Path, target: &str, output: &Path) -> Result<()> {
    let mut configurations = serde_json::Map::new();
    for feature in [
        "default",
        "storage-spike",
        "sprite-demo",
        "proxy",
        "all-features",
    ] {
        let flags = if feature == "default" {
            vec![]
        } else if feature == "all-features" {
            vec!["--all-features"]
        } else {
            vec!["--features", feature]
        };
        let metadata: Value = serde_json::from_str(&run(Command::new("cargo")
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--filter-platform",
                target,
            ])
            .args(&flags)
            .current_dir(root))?)?;
        let tree = run(Command::new("cargo")
            .args([
                "tree",
                "-p",
                "aegis-broker",
                "--locked",
                "--offline",
                "--target",
                target,
                "--edges",
                "normal,build,dev",
                "--no-dedupe",
                "--prefix",
                "none",
                "--format",
                "{p}|{f}",
            ])
            .args(&flags)
            .current_dir(root))?;
        let mut selected = std::collections::BTreeMap::<
            (String, String),
            std::collections::BTreeSet<String>,
        >::new();
        for line in tree.lines() {
            let (package, features) = line.split_once('|').ok_or("invalid cargo tree")?;
            let mut words = package.split_whitespace();
            let name = words.next().ok_or("missing name")?.to_owned();
            let version = words
                .next()
                .ok_or("missing version")?
                .trim_start_matches('v')
                .to_owned();
            selected.entry((name, version)).or_default().extend(
                features
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            );
        }
        let mut packages = Vec::new();
        for ((name, version), features) in selected {
            let matches: Vec<_> = metadata["packages"]
                .as_array()
                .ok_or("missing metadata")?
                .iter()
                .filter(|p| p["name"] == name && p["version"] == version)
                .collect();
            if matches.len() != 1 {
                return Err("ambiguous package identity".into());
            }
            let p = matches[0];
            if !p["source"].is_null() {
                packages.push(json!({"name":name,"version":version,"features":features,"source":p["source"],"license":p["license"],"rust_version":p["rust_version"]}));
            }
        }
        configurations.insert(feature.into(), json!(packages));
    }
    fs::write(
        output,
        serde_json::to_vec_pretty(
            &json!({"target":target,"selection":"cargo tree normal/build/dev graph; not compilation or security attestation","configurations":configurations}),
        )?,
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("missing root")?
        .to_owned();
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, tag, target] if command == "package" => package(&root, tag, target),
        [command, target, output] if command == "inventory" => {
            inventory(&root, target, Path::new(output))
        }
        [command] if command == "check" => {
            let status = Command::new("sh")
                .arg("scripts/check.sh")
                .current_dir(root)
                .stdin(Stdio::inherit())
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err("checks failed".into())
            }
        }
        _ => Err(
            "Usage: cargo run -p xtask -- package TAG TARGET | inventory TARGET OUTPUT | check"
                .into(),
        ),
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn checksums_are_byte_identical_lf_on_all_platforms() {
        let result = super::checksum(b"abc", "aegis-windows.zip");
        assert_eq!(result, b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  aegis-windows.zip\n");
        assert!(!result.contains(&b'\r'));
    }
}
