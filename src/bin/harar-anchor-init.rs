use std::{
    collections::HashMap,
    env, fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{Duration, Timelike as _, Utc};
use ed25519_dalek::SigningKey;
use tana_cli_core::build_bootstrap_anchor_set;

fn main() {
    if let Err(error) = run() {
        eprintln!("harar-anchor-init: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = parse_args()?;
    let root_a = read_signing_key(required(&args, "--root-a-key")?)?;
    let root_b = read_signing_key(required(&args, "--root-b-key")?)?;
    let release = read_signing_key(required(&args, "--release-key")?)?;
    let freshness = read_signing_key(required(&args, "--freshness-key")?)?;
    let output_dir = PathBuf::from(required(&args, "--output-dir")?);
    let issued_at = Utc::now()
        .with_nanosecond(0)
        .context("round ceremony timestamp")?;
    let expires_at = issued_at + Duration::days(365);
    let bootstrap = build_bootstrap_anchor_set(
        &root_a, &root_b, &release, &freshness, issued_at, expires_at,
    )?;

    fs::create_dir_all(&output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;
    write_public_file(&output_dir.join("anchor-set.json"), &bootstrap.anchor_set)?;
    write_public_file(
        &output_dir.join("anchor-set.sig.json"),
        &bootstrap.signatures,
    )?;
    println!(
        "wrote generation-1 anchor-set.json and anchor-set.sig.json to {}",
        output_dir.display()
    );
    Ok(())
}

fn parse_args() -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        if !matches!(
            flag.as_str(),
            "--root-a-key" | "--root-b-key" | "--release-key" | "--freshness-key" | "--output-dir"
        ) {
            bail!("unknown argument {flag}; expected four key-path flags and --output-dir");
        }
        let value = args
            .next()
            .with_context(|| format!("{flag} requires a path"))?;
        if values.insert(flag.clone(), value).is_some() {
            bail!("duplicate argument {flag}");
        }
    }
    Ok(values)
}

fn required<'a>(args: &'a HashMap<String, String>, name: &str) -> Result<&'a str> {
    args.get(name)
        .map(String::as_str)
        .with_context(|| format!("missing required argument {name}"))
}

fn read_signing_key(path: &str) -> Result<SigningKey> {
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private key path {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("private key path {} must be a regular file", path.display());
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("private key path {} must have mode 0600", path.display());
    }
    let bytes =
        fs::read(path).with_context(|| format!("read private key path {}", path.display()))?;
    let mut raw: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "private key path {} must contain exactly 32 raw bytes",
            path.display()
        )
    })?;
    let key = SigningKey::from_bytes(&raw);
    raw.fill(0);
    Ok(key)
}

fn write_public_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("create {} without overwriting", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
