use dialoguer::{theme::ColorfulTheme, Select};
use eyre::Result;
use ipnet::IpNet;
use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    vpns: Vec<VpnConfig>,
}

impl Config {
    pub fn get_vpn_config<'a>(&'a self, name: &str) -> Option<&VpnConfig> {
        self.vpns.iter().find(|conf| conf.name == name)
    }

    pub fn select_name(&self) -> Result<String> {
        let names: Vec<&str> = self.vpns.iter().map(|s| s.name.as_str()).collect();
        let index = Select::with_theme(&ColorfulTheme::default())
            .items(&names)
            .with_prompt("Which proxy should be started?")
            .default(0)
            .interact()?;
        Ok(self.vpns[index].name.to_owned())
    }
}

#[derive(Debug, Deserialize)]
pub struct VpnConfig {
    pub name: String,
    pub tunneled_networks: Vec<IpNet>,
    pub domains: Vec<String>,
    pub dns_server: IpAddr,
    pub password_name: PathBuf,
}
