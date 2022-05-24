mod config;
mod util;

use color_eyre::Report;
use config::{Config, VpnConfig};
use dbus::nonblock::{Connection, Proxy, SyncConnection};
use dbus_tokio::connection;
use eyre::{ensure, eyre, Result};
use libc::{AF_INET, AF_INET6, AF_UNSPEC};
use std::{
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use crate::util::{cache_sudo, get_credentials, is_pid_alive};
use clap::{Parser, Subcommand};
use tokio::{fs, process::Command, signal, task::spawn_blocking, time::sleep};
use tokio_stream::{wrappers::ReadDirStream, StreamExt};
use tracing::{info, warn};

const RUN_DIR: &str = "/var/run/corprox";
const PIDFILE_NAME: &str = "pidfile";
const CREDSFILE_NAME: &str = "creds";
const VPN_CONFIG_FILENAME: &str = "config.ovpn";

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    println!("signal received, starting graceful shutdown");
}

/// A cli utility to run a corporate VPN while preserving
/// normal routing. Modifies the OpenVPN config to only route
/// specfied ip nets via the vpn. Also sets up correct DNS resolution
/// with systemd-resolved.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Server config file location. Default is `$XDG_CONFIG_HOME/corprox/corprox.toml`
    #[clap(short, long)]
    config_file: Option<PathBuf>,

    /// Select the VPN not interactively
    #[clap(short, long)]
    vpn_name: Option<String>,

    /// Specify username on the command line. If omitted will try to use GPG file in config. If
    /// specfied, `password` has to be specified too.
    #[clap(short, long)]
    username: Option<String>,
    /// Specify password on the command line. If omitted will try to use GPG file in config. If
    /// specfied, `username` has to be specified too.
    #[clap(short, long)]
    password: Option<String>,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the corporate vpn
    Start,
    /// Stop the corporate vpn
    Stop,
}

fn fix_config(vpn_config: &VpnConfig, config: String, run_path: &Path) -> Result<String> {
    let mut original_lines: Vec<String> = config
        .lines()
        .map(|s| {
            s.to_owned()
            //            if s.starts_with("dev") {
            //                format!("dev {}", DEV_NAME)
            //            } else {
            //                s.to_owned()
            //            }
        })
        .collect();

    let mut prefix = vec![
        format!("daemon openvpn-{}", vpn_config.name),
        format!("cd {:?}", run_path),
        format!("writepid {:?}", run_path.join(PIDFILE_NAME)),
        format!("auth-user-pass {}", CREDSFILE_NAME),
        format!("\n### START ORIGINAL CONFIG ###"),
    ];
    let mut postfix = vec![
        format!("### END ORIGINAL CONFIG ###\n"),
        format!("route-nopull"),
    ];
    for net_addr in &vpn_config.tunneled_networks {
        postfix.push(format!("route {} {}", net_addr.addr(), net_addr.netmask()));
    }

    prefix.append(&mut original_lines);
    prefix.append(&mut postfix);
    Ok(prefix.join("\n"))
}

fn copy_files(from_path: &Path, to_path: &Path) -> Result<PathBuf> {
    let mut config_file_path = None;
    for entry in std::fs::read_dir(from_path)? {
        let path = entry?.path();
        let extension = path.extension();
        if extension == Some(OsStr::new("crt")) || extension == Some(OsStr::new("key")) {
            let to_path = to_path.join(path.file_name().unwrap());
            info!("Copying {:?} to {:?}", path, to_path);
            std::fs::copy(path, to_path)?;
        } else if extension == Some(OsStr::new("ovpn")) {
            ensure!(
                config_file_path.is_none(),
                "more than one .ovpn file exists in config dir"
            );
            config_file_path = Some(path);
        }
    }
    config_file_path.ok_or(eyre!(".ovpn file is missing"))
}

async fn get_pid(run_path: &Path) -> Result<Option<u32>> {
    let pid_path = run_path.join(PIDFILE_NAME);
    if !pid_path.is_file() {
        return Ok(None);
    }
    Ok(fs::read_to_string(&pid_path).await?.trim().parse().ok())
}

async fn get_interface_number(pid: u32) -> Result<i32> {
    // TODO: is it always 5?
    let output = Command::new("grep")
        .arg("-h")
        .arg("^iff:")
        .arg(format!("/proc/{}/fdinfo/5", pid))
        .output()
        .await?;
    ensure!(
        output.status.success(),
        "could not get interface name for openvpn tunnel: {}",
        String::from_utf8(output.stderr)?
    );
    let interface_name = String::from_utf8(output.stdout)?
        .split_whitespace()
        .nth(1)
        .ok_or(eyre!("could not get interface name!"))?
        .to_owned();
    let path = PathBuf::from(&format!("/sys/class/net/{}/ifindex", interface_name));
    let index = fs::read_to_string(&path).await?.trim().parse()?;
    Ok(index)
}

const DBUS_METHOD_OBJ: &str = "org.freedesktop.resolve1.Manager";

async fn setup_resolved(
    vpn_config: &VpnConfig,
    dbus_conn: Arc<SyncConnection>,
    interface_number: i32,
) -> Result<()> {
    let proxy = Proxy::new(
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        Duration::from_secs(2),
        dbus_conn,
    );
    let mut domains = Vec::new();
    for domain in &vpn_config.domains {
        domains.push((domain, true));
    }
    let mut dnses = Vec::new();
    match vpn_config.dns_server {
        std::net::IpAddr::V4(addr) => {
            dnses.push((AF_INET, addr.octets().to_vec()));
        }
        std::net::IpAddr::V6(addr) => {
            dnses.push((AF_INET6, addr.octets().to_vec()));
        }
    }

    proxy
        .method_call(
            DBUS_METHOD_OBJ,
            "SetLinkDefaultRoute",
            (interface_number, false),
        )
        .await?;
    proxy
        .method_call(
            DBUS_METHOD_OBJ,
            "SetLinkDomains",
            (interface_number, domains),
        )
        .await?;
    proxy
        .method_call(DBUS_METHOD_OBJ, "SetLinkDNS", (interface_number, dnses))
        .await?;
    Ok(())
}

async fn start(
    vpn_config: &VpnConfig,
    run_path: &Path,
    ctx_dir: &Path,
    username: Option<String>,
    password: Option<String>,
    dbus_conn: Arc<SyncConnection>,
) -> Result<()> {
    let vpn_config_path = ctx_dir.join(&vpn_config.name);
    info!("Run path is {:?}", &run_path);
    info!("VPN config path is {:?}", &vpn_config_path);
    // [TODO]: Use nice syntax here once that is stable
    if let Some(pid) = get_pid(run_path).await? {
        if is_pid_alive(pid).await? {
            warn!(
                "A vpn instance for {} seems to be running with pid {}!",
                vpn_config.name, pid
            );
            println!("The vpn seems to be running already, stop it first!");
            return Ok(());
        }
    }
    //    println!("I need sudo privileges to start OpenVPN:");
    //    cache_sudo().await?;

    fs::create_dir_all(&run_path).await?;
    let config_file_path = {
        let from_path = vpn_config_path.clone();
        let to_path = run_path.to_owned();
        spawn_blocking(move || copy_files(&from_path, &to_path)).await??
    };
    let config_content = fix_config(
        vpn_config,
        fs::read_to_string(config_file_path).await?,
        &run_path,
    )?;
    let out_path = run_path.join(VPN_CONFIG_FILENAME);
    info!("Writing config to {:?}", out_path);
    fs::write(run_path.join("config.ovpn"), &config_content).await?;
    let (username, password) = if let Some(creds) = username.and_then(|u| password.map(|p| (u, p))) {
        creds
    } else {
        get_credentials(&vpn_config.password_name).await?
    };
    let creds_path = run_path.join(CREDSFILE_NAME);
    fs::write(creds_path, format!("{}\n{}\n", username, password)).await?;

    let output = Command::new("openvpn")
        .arg("--config")
        .arg(&out_path)
        .arg("--auth-user-pass")
        .arg(run_path.join(CREDSFILE_NAME))
        .output()
        .await?;

    info!("Starting openvpn deamon...");
    ensure!(
        output.status.success(),
        "could not start openvpn: {}",
        String::from_utf8(output.stderr)?
    );

    info!("Waiting a bit for openvpn to give out pid...");
    sleep(Duration::from_millis(5000)).await;

    let pid = get_pid(run_path)
        .await?
        .ok_or(eyre!("openvpn does not seem to be running"))?;
    let ifnum = get_interface_number(pid).await?;
    info!("Openvpn's interface number is {}", ifnum);

    info!("Setting up systemd resolve to correctly resolve dns requests...");
    setup_resolved(vpn_config, dbus_conn, ifnum).await?;

    Ok(())
}
async fn stop(vpn_config: &VpnConfig, run_path: &Path) -> Result<()> {
    let pid = get_pid(run_path)
        .await?
        .ok_or(eyre!("cannot get vpn pid, is it running?"))?;
    ensure!(
        is_pid_alive(pid).await?,
        "the vpn does not seem to be running"
    );
    let output = Command::new("kill").arg(pid.to_string()).output().await?;
    ensure!(
        output.status.success(),
        "could not stop openvpn: {}",
        String::from_utf8(output.stderr)?
    );
    info!("Stopped openvpn!");
    Ok(())
}

async fn run(
    command: Commands,
    vpn_config: &VpnConfig,
    run_path: &Path,
    ctx_dir: &Path,
    username: Option<String>,
    password: Option<String>,
    dbus_conn: Arc<SyncConnection>,
) -> Result<()> {
    match command {
        Commands::Start => start(vpn_config, run_path, ctx_dir, username, password, dbus_conn).await?,
        Commands::Stop => stop(vpn_config, run_path).await?,
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let (resource, conn) = connection::new_system_sync()?;
    let mut resource_handle = tokio::spawn(async { resource.await });

    tracing_subscriber::fmt::init();
    color_eyre::install()?;

    let cli = Cli::parse();

    ensure!(cli.username.is_some() == cli.password.is_some(), "You have to specify both username and password or none of both"); 

    let config_path = cli
        .config_file
        .map(|d| Ok::<PathBuf, Report>(d))
        .unwrap_or_else(|| {
            Ok([&env::var("XDG_CONFIG_HOME")?, "corprox/corprox.toml"]
                .iter()
                .collect::<PathBuf>())
        })?;
    let config: Arc<Config> = Arc::new(toml::from_str(&fs::read_to_string(&config_path).await?)?);
    // Safe because config_pathis a file
    let ctx_dir = config_path.parent().unwrap();
    let vpn_name = if let Some(name) = cli.vpn_name {
        name
    } else {
        let config = config.clone();
        spawn_blocking(move || config.select_name()).await??
    };
    info!("Selected vpn config {}", vpn_name);
    let vpn_config = config
        .get_vpn_config(&vpn_name)
        .ok_or(eyre!("Unknown vpn config name"))?;

    let run_path = Path::new(RUN_DIR).join(&vpn_config.name);


    let mut result: Result<()> = Ok(());
    tokio::select! {
        _ = shutdown_signal() => {
            println!("User cancelled, running cleanup...");

        },
        new_result = run(cli.command, &vpn_config, &run_path, &ctx_dir, cli.username, cli.password, conn) => {
            result = new_result;
        },
        new_result = &mut resource_handle => {
            result = Err(new_result?.into());
        }
    }
    // make sure creds are deleted
    let creds_path = run_path.join(CREDSFILE_NAME);
    if creds_path.exists() {
        info!("Removing credentials file!");
        fs::write(&creds_path, "").await?;
        fs::remove_file(creds_path).await?;
    }
    resource_handle.abort();

    result?;

    Ok(())
}
