use std::collections::HashMap;

use authentik::{configure_authentik_users, AuthentikConfig};
use clap::Parser;
use gitlab::configure_gitlab;
use keycloak::{configure_keycloak_users, KeycloakConfig};
use serde_with::skip_serializing_none;
use tokio;
use website::{configure_website_users, WebsiteConfig};

mod authentik;
mod gitlab;
mod keycloak;
mod website;
fn true_bool() -> bool {
    true
}
fn false_bool() -> bool {
    false
}

#[derive(Parser)]
#[command(
    version,
    author = "Florian Schubert",
    about = "Program um die Benutzer der Fachschaft Informatik zu verwalten",
    name = "benutzerverwaltungstool",
    color = clap::ColorChoice::Always
)]
struct Args {
    #[clap(short, long)]
    config: String,
    #[clap(short, long)]
    users: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct Config {
    keycloak: Option<KeycloakConfig>,
    authentik: Option<AuthentikConfig>,
    website: Option<WebsiteConfig>,
    gitlab: Option<gitlab::GitLabConfig>,
    auth_client_id: String,
    #[serde(default = "false_bool")]
    delete_users: bool,
    realm: String,
}

#[skip_serializing_none]
#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub(crate) struct UserConfig {
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    roles: Vec<String>,
    #[serde(default = "true_bool")]
    enabled: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //Set Log Level to Info
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args: Args = Args::parse();
    let config = std::fs::read_to_string(args.config)?;
    let config: Config = serde_json::from_str(&config)?;

    let user_configs = std::fs::read_to_string(args.users)?;
    let user_configs: HashMap<String, UserConfig> = serde_json::from_str(&user_configs)?;

    if let Some(keycloak_config) = &config.keycloak {
        configure_keycloak_users(&user_configs, &keycloak_config).await?;
    }

    if let Some(authentik_config) = &config.authentik {
        configure_authentik_users(&user_configs, &authentik_config).await?;
    }

    if let Some(gitlab_config) = &config.gitlab {
        configure_gitlab(&user_configs, gitlab_config).await?;
    }

    if let Some(website_config) = &config.website {
        configure_website_users(&user_configs, website_config).await?;
    }

    Ok(())
}
