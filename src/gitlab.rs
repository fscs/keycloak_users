use std::collections::HashMap;

use crate::UserConfig;
use gitlab::api::common::AccessLevel;
use gitlab::Gitlab;
use gitlab::api::{self, Query};
use log::info;

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct GitLabConfig {
    token: String,
    url: String,
    group_id: u64,
    owner_role: String,
    maintainer_role: String
}

#[derive(serde::Deserialize, PartialEq, Eq, Debug)]
pub struct GitlabUser {
    id: u64,
    username: String
}

pub async fn configure_gitlab(user_configs: &HashMap<String, UserConfig>, config: &GitLabConfig) -> anyhow::Result<()> {
    let client = Gitlab::new(config.url.to_owned(), config.token.to_owned())?;

    let users = user_configs.iter()
        .filter(|user| user.1.roles.iter().any(|r| r == &config.maintainer_role || r == &config.owner_role))
        .inspect(|user| info!("gitlab: {:?}", user))
        .filter_map::<Vec<GitlabUser>, _>(|user| {
            api::users::Users::builder()
            .username(user.0)
            .build()
            .unwrap()
            .query(&client)
            .ok()
        })
        .filter_map(|mut v| v.pop())
        .collect::<Vec<GitlabUser>>();

    info!("gitlab: {:?}", users);

    let current_group_members : Vec<GitlabUser> = api::groups::members::GroupMembers::builder().group(config.group_id).build()?.query(&client)?;
    info!("current_group_members: {:?}", current_group_members);

    let (users_to_update, users_to_remove) : (Vec<_>, Vec<_>) = current_group_members
        .into_iter()
        .partition(|m| users.contains(m));

    info!("Users to update {:?}", users_to_update);
    info!("Users to remove {:?}", users_to_remove);

    let users_to_create : Vec<_> = users.into_iter()
        .filter(|u| !users_to_update.contains(u))
        .collect();

    info!("Users to create {:?}", users_to_create);

    users_to_create
        .iter()
        .try_for_each(|user| {
            let _ = api::ignore(api::groups::members::AddGroupMember::builder()
                .group(config.group_id)
                .user(user.id)
                .access_level(if user_configs[&user.username].roles.contains(&config.owner_role) {AccessLevel::Owner} else {AccessLevel::Maintainer})
                .build()?)
                .query(&client)?;
            anyhow::Ok(())
        })?;

    users_to_update
        .iter()
        .try_for_each(|user| {
            let _ = api::ignore(api::groups::members::EditGroupMember::builder()
                .access_level(if user_configs[&user.username].roles.contains(&config.owner_role) {AccessLevel::Owner} else {AccessLevel::Maintainer})
                .user(user.id)
                .group(config.group_id)
                .build()?)
                .query(&client)?;
            anyhow::Ok(())
        })?;

    users_to_remove
        .iter()
        .try_for_each(|user| {
            let _ = api::ignore(api::groups::members::RemoveGroupMember::builder()
                .user(user.id)
                .group(config.group_id)
                .build()?)
                .query(&client)?;
            anyhow::Ok(())
        })?;
    Ok(())
}
