use std::collections::HashMap;




use crate::UserConfig;
use gitlab::Gitlab;
use gitlab::api::{self, Query};

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct GitLabConfig {
    token: String,
    url: String,
    group_id: u64,
    owner_role: String
}

#[derive(serde::Deserialize, PartialEq, Eq)]
pub struct GitlabUser {
    id: u64,
    username: String
}

pub async fn configure_gitlab(user_configs: &HashMap<String, UserConfig>, config: &GitLabConfig) -> anyhow::Result<()> {
    let client = Gitlab::new(config.url.to_owned(), config.token.to_owned())?;

    let users = user_configs.iter().map(|user| {
        api::users::Users::builder()
          .username(user.0)
          .build()
          .unwrap()
          .query(&client)
          .unwrap()
    }).collect::<Vec<GitlabUser>>();

    let current_group_members : Vec<GitlabUser> = api::groups::members::GroupMembers::builder().group(config.group_id).build()?.query(&client)?;

    let (users_to_update, users_to_remove) : (Vec<_>, Vec<_>) = current_group_members
        .into_iter()
        .partition(|m| users.contains(m));

    let users_to_create : Vec<_> = users.into_iter()
        .filter(|u| users_to_update.contains(u))
        .collect();

    users_to_create
        .iter()
        .try_for_each(|user| {
            api::groups::members::AddGroupMember::builder()
                .group(config.group_id)
                .user(user.id)
                .access_level(api::common::AccessLevel::Maintainer)
                .build()?
                .query(&client)?;
            anyhow::Ok(())
        })?;

    users_to_update
        .iter()
        .try_for_each(|user| {
            api::groups::members::EditGroupMember::builder()
                .access_level(api::common::AccessLevel::Maintainer)
                .user(user.id)
                .build()?
                .query(&client)?;
            anyhow::Ok(())
        })?;

    users_to_remove
        .iter()
        .try_for_each(|user| {
            api::groups::members::RemoveGroupMember::builder()
                .user(user.id)
                .build()?
                .query(&client)?;
            anyhow::Ok(())
        })?;
    Ok(())
}
