use std::{
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
};

use eyre::eyre;
use eyre::{ensure, Result};
use tokio::process::Command;
use tracing::{info, warn};

const PASSWORD_STORE: &str = ".password-store";

pub async fn is_pid_alive(pid: u32) -> Result<bool> {
    let mut output = Command::new("ps")
        .arg("-h")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .await?;
    Ok(output.status.success())
}

pub async fn cache_sudo() -> Result<()> {
    let output = Command::new("sudo").arg("-v").output().await?;
    ensure!(
        output.status.success(),
        "could not aquire sudo privileges: {}",
        String::from_utf8(output.stderr)?
    );
    Ok(())
}

pub async fn get_credentials(password_path: &Path) -> Result<(String, String)> {
    let mut path: PathBuf = [&env::var("HOME")?, PASSWORD_STORE].iter().collect();
    path.push(password_path);
    let mut filename = path
        .file_name()
        .ok_or(eyre!("password path has to be a file path"))?
        .to_owned();
    filename.push(".gpg");
    path.set_file_name(filename);

    info!("Getting credentials from {:?}", path);
    let output = Command::new("gpg")
        .arg("--pinentry-mode=loopback")
        .arg("-q")
        .arg("--decrypt")
        .arg(path)
        .output()
        .await?;
    ensure!(
        output.status.success(),
        "error while decripting password: {}",
        String::from_utf8(output.stderr)?
    );
    let mut lines: Vec<String> = String::from_utf8(output.stdout)?
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    ensure!(lines.len() >= 2, "password file does not include username");
    let mut username = None;
    for (name, value) in lines.iter().skip(1).filter_map(|l| l.split_once(":")) {
        if name.trim() == "username" || name.trim() == "email" {
            if username.is_some() {
                warn!("Multiple fields with username in password file, using last");
            }
            username = Some(value.trim().to_owned());
        }
    }
    username
        .ok_or(eyre!("password file does not include username"))
        .map(|username| (username, lines.remove(0)))
}
