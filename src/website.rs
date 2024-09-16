use std::collections::HashMap;

use anyhow::Error;
use oauth2::{
    basic::BasicClient,
    http::header::USER_AGENT,
    reqwest::{async_http_client, http_client},
    AuthUrl, ClientId, ClientSecret, RedirectUrl, ResourceOwnerPassword, ResourceOwnerUsername,
    Scope, TokenResponse, TokenUrl,
};
use uuid::Uuid;

use crate::{authentik, UserConfig};

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct WebsiteConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct WebsiteUser {
    id: Uuid,
    name: String,
}

pub async fn get_token(websiteconfig: WebsiteConfig) -> Result<String, Error> {
    let oauth = BasicClient::new(
        ClientId::new(websiteconfig.client_id),
        Some(ClientSecret::new(websiteconfig.client_secret)),
        AuthUrl::new("https://auth.inphima.de/application/o/authorize/".to_string())?,
        Some(TokenUrl::new(
            "https://auth.inphima.de/application/o/token/".to_string(),
        )?),
    );

    let toen = oauth
        .set_redirect_uri(RedirectUrl::new("http://localhost".to_string()).unwrap())
        .exchange_password(
            &ResourceOwnerUsername::new(websiteconfig.username),
            &ResourceOwnerPassword::new(websiteconfig.password),
        )
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .request_async(async_http_client)
        .await;
    println!("{:?}", toen);
    Ok("".to_string())
}

pub async fn configure_website_users(
    user_configs: &HashMap<String, UserConfig>,
    website_config: &WebsiteConfig,
) -> Result<(), Error> {
    let users = get_all_users(website_config.clone()).await?;

    let users_to_create = user_configs
        .iter()
        .filter(|user| {
            !users.iter().any(|w| {
                w.name
                    == format!(
                        "{} {}",
                        user.1.first_name.clone().unwrap_or("".to_string()),
                        user.1.last_name.clone().unwrap_or("".to_string())
                    )
            })
        })
        .filter(|user| user.1.roles.iter().any(|r| r.contains("Informatik")))
        .collect::<HashMap<_, _>>();

    for user in users_to_create {
        create_user(
            website_config.clone(),
            format!(
                "{} {}",
                user.1.first_name.clone().unwrap_or("".to_string()),
                user.1.last_name.clone().unwrap_or("".to_string())
            ),
        )
        .await?;
    }

    Ok(())
}

async fn get_all_users(website_config: WebsiteConfig) -> Result<Vec<WebsiteUser>, Error> {
    let response = reqwest::Client::new()
        .get(website_config.url + "/api/persons/")
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap()
        .json::<Vec<WebsiteUser>>()
        .await
        .unwrap();

    Ok(response)
}

async fn create_user(website_config: WebsiteConfig, username: String) -> Result<(), Error> {
    let token = get_token(website_config.clone()).await?;
    println!("{}", token);
    let _response = reqwest::Client::new()
        .put(website_config.url + "/api/persons/")
        .header("Content-Type", "application/json")
        .header("Cookie", &format!("access_token={};", token))
        .body(format!("{{\"name\": \"{}\"}}", username))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    println!("{}", format!("{{\"name\": {}}}", username));

    println!("{}", _response);

    Ok(())
}
