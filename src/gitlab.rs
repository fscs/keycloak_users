use oauth2::{reqwest::http_client, AuthUrl, ClientId, Scope, TokenUrl};
use serde_json::json;

use crate::UserConfig;
use gitlab::Gitlab;
use gitlab::api::{self, users, groups};


pub struct GitLabConfig {
    token: String,
    url: String,
}

pub async fn configure_gitlab(user_configs: &Vec<UserConfig>, config: &GitLabConfig) -> anyhow::Result<()> {
    let client = Gitlab::new(config.url.to_owned(), config.token.to_owned())?;

    let users = user_configs.iter().map(|user| {
        api::users::Users::builder()
          .username(user.username)
          .build()
          .

    });
    api::users::Users::builder()
    

    Ok(())
}