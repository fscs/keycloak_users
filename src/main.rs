use std::collections::HashMap;

use authentik::{configure_authentik_users, AuthentikConfig};
use clap::Parser;
use gitlab::configure_gitlab;
use keycloak::{configure_keycloak_users, KeycloakConfig};
use matrix::configure_matrix;
use serde_with::skip_serializing_none;
use tokio;

mod authentik;
mod gitlab;
mod keycloak;
mod matrix;
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
    gitlab: Option<gitlab::GitLabConfig>,
    matrix: Option<matrix::MatrixConfig>,
}

#[skip_serializing_none]
#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub(crate) struct UserConfig {
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    matrix_id: Option<String>,
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

    if let Some(matrix_config) = &config.matrix {
        configure_matrix(&user_configs, matrix_config).await?;
    }

    Ok(())
}
