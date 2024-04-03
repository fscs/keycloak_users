use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::AccessToken;
use oauth2::ClientId;
use oauth2::TokenResponse;
use log::*;
use serde_json::json;

use crate::true_bool;
use crate::UserConfig;

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
    pub username: String,
    pub password: String,
    pub client_id: String,
}


#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct KeycloakUser {
    id: String,
    username: String,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    #[serde(default = "true_bool")]
    enabled: bool,
}

struct KeycloakClient {
    base_url: String,
    realm: String,
    token: AccessToken,
    reqwest_client: reqwest::Client,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
struct KeycloakRole {
    id: String,
    name: String,
}

pub async fn configure_keycloak_users(users: &Vec<UserConfig>, keycloak_config: &KeycloakConfig) -> anyhow::Result<()> {
    let client = KeycloakClient::new(
        keycloak_config.url.clone(),
        keycloak_config.realm.clone(),
        keycloak_config.username.clone(),
        keycloak_config.password.clone(),
        keycloak_config.client_id.clone(),
    ).await?;

    let keycloak_users = client.get_all_users().await?;

    let users_to_create = users.iter().filter(|user| {
        !keycloak_users.iter().any(|keycloak_user| keycloak_user.username == user.username)
    }).collect::<Vec<_>>();
    client.create_users(&users_to_create).await?;


    let users_to_update = keycloak_users.iter().filter(|keycloak_user| {
        users.iter().any(|user| user.username == keycloak_user.username)
    }).collect::<Vec<_>>();
    client.update_users(&users_to_update, users).await?;
    client.update_roles(&users_to_update, users).await?;

    let users_to_delete = keycloak_users.iter().filter(|keycloak_user| {
        !users.iter().any(|user| user.username == keycloak_user.username)
    }).collect::<Vec<_>>();
    client.delete_users(&users_to_delete).await?;

    Ok(())
}

impl KeycloakClient {
    async fn new(
        base_url: String,
        realm: String,
        user: String,
        password: String,
        client_id: String
    ) -> anyhow::Result<Self> {
        let oauth_client = BasicClient::new(
            ClientId::new(client_id),
            None,
            oauth2::AuthUrl::new(format!(
                "{}/realms/master/protocol/openid-connect/auth",
                base_url
            ))
            .unwrap(),
            Some(
                oauth2::TokenUrl::new(format!(
                    "{}/realms/master/protocol/openid-connect/token",
                    base_url
                ))
                .unwrap(),
            ),
        );
        // Get a Token with Password Grant
        let token = oauth_client
            .exchange_password(
                &oauth2::ResourceOwnerUsername::new(user.clone()),
                &oauth2::ResourceOwnerPassword::new(password.clone()),
            )
            .request_async(async_http_client)
            .await?
            .access_token()
            .clone();

        Ok(KeycloakClient {
            base_url,
            realm,
            token,
            reqwest_client: reqwest::Client::new(),
        })
    }

    async fn create_users(
        &self,
        users: &Vec<&UserConfig>,
    ) -> anyhow::Result<()> {
        for user in users {
            let user = self
                .reqwest_client
                .post(format!(
                    "{}/admin/realms/{}/users",
                    self.base_url, self.realm
                ))
                .bearer_auth(&self.token.secret())
                .json(&json!(
                    {
                        "username": user.username,
                        "firstName": user.first_name,
                        "lastName": user.last_name,
                        "email": user.email,
                        "enabled": user.enabled,
                    }
                ))
                .send()
                .await?
                .text()
                .await?;
            info!("Created User: {:?}", user);
        }
        Ok(())
    }

    async fn get_all_users(&self) -> anyhow::Result<Vec<KeycloakUser>> {
        info!("Getting all users from Keycloak");
        // Create a request
        Ok(self
            .reqwest_client
            .get(format!(
                "{}/admin/realms/{}/users",
                self.base_url, self.realm
            ))
            .bearer_auth(self.token.secret())
            .send()
            .await?
            .json::<Vec<KeycloakUser>>()
            .await?)
    }

    async fn disable_users(&self, users: &Vec<&KeycloakUser>) -> anyhow::Result<()> {
        for user in users {
            info!("Disabling user: {}", user.username);
            let _ = self
                .reqwest_client
                .put(format!(
                    "{}/admin/realms/{}/users/{}",
                    self.base_url, self.realm, user.id
                ))
                .bearer_auth(self.token.secret())
                .json(&json!({
                    "enabled": false
                }))
                .send()
                .await?;
        }
        Ok(())
    }

    async fn delete_users(&self, users: &Vec<&KeycloakUser>) -> anyhow::Result<()> {
        for user in users {
            info!("Deleting user: {}", user.username);
            let _ = self
                .reqwest_client
                .delete(format!(
                    "{}/admin/realms/{}/users/{}",
                    self.base_url, self.realm, user.id
                ))
                .bearer_auth(self.token.secret())
                .json(&json!({
                    "enabled": false
                }))
                .send()
                .await?;
        }
        Ok(())
    }

    async fn get_all_realm_roles(&self) -> anyhow::Result<Vec<KeycloakRole>> {
        info!("Getting all realm roles from Keycloak");
        Ok(self
            .reqwest_client
            .get(format!(
                "{}/admin/realms/{}/roles",
                self.base_url, self.realm
            ))
            .bearer_auth(self.token.secret())
            .send()
            .await?
            .json::<Vec<KeycloakRole>>()
            .await?)
    }

    async fn get_realm_roles(&self, user: &KeycloakUser) -> anyhow::Result<Vec<KeycloakRole>> {
        info!("Getting realm roles for user: {}", user.username);
        Ok(self
            .reqwest_client
            .get(format!(
                "{}/admin/realms/{}/users/{}/role-mappings/realm",
                self.base_url, self.realm, user.id
            ))
            .bearer_auth(self.token.secret())
            .send()
            .await?
            .json::<Vec<KeycloakRole>>()
            .await?)
    }

    fn roles_to_add(
        config_roles: &Vec<String>,
        keycloak_roles: &Vec<KeycloakRole>,
        existing_roles: &Vec<KeycloakRole>,
    ) -> Vec<KeycloakRole> {
        keycloak_roles
            .iter()
            .filter(|role| config_roles.contains(&role.name))
            .filter(|role| !existing_roles.contains(role))
            .cloned()
            .collect()
    }

    fn roles_to_remove(config_roles: &Vec<String>, keycloak_roles: &Vec<KeycloakRole>) -> Vec<KeycloakRole> {
        keycloak_roles
            .iter()
            .filter(|role| !config_roles.contains(&role.name))
            .cloned()
            .collect()
    }

    async fn update_roles(
        &self,
        users_keycloak: &Vec<&KeycloakUser>,
        user_configs: &Vec<UserConfig>,
    ) -> anyhow::Result<()> {
        info!("Updating roles for users");
        let keycloak_roles = self.get_all_realm_roles().await?;
        for user in users_keycloak {
            let configured_roles = Self::get_roles_in_config(user_configs, user);
            let existing_roles = self.get_realm_roles(user).await?;
            let roles_to_add =
                Self::roles_to_add(&configured_roles, &keycloak_roles, &existing_roles);
            let roles_to_remove = Self::roles_to_remove(&configured_roles, &existing_roles);

            self.update_user_roles(&user.id, &roles_to_add, &roles_to_remove)
                .await?;
        }
        Ok(())
    }

    async fn update_user_roles(
        &self,
        user_id: &String,
        roles_to_add: &Vec<KeycloakRole>,
        roles_to_remove: &Vec<KeycloakRole>,
    ) -> anyhow::Result<()> {
        info!("Updating roles for user: {}", user_id);
        if !roles_to_add.is_empty() {
            match self
                .reqwest_client
                .post(format!(
                    "{}/admin/realms/{}/users/{}/role-mappings/realm",
                    self.base_url, self.realm, user_id
                ))
                .bearer_auth(self.token.secret())
                .json(&json!(roles_to_add))
                .send()
                .await?
                .status()
            {
                reqwest::StatusCode::NO_CONTENT => {
                    info!("Added roles: {:?} to {:?}", roles_to_add, user_id)
                }
                status => error!("Failed to add roles to user: {}", status),
            }
        }
        self.reqwest_client
            .delete(format!(
                "{}/admin/realms/{}/users/{}/role-mappings/realm",
                self.base_url, self.realm, user_id
            ))
            .bearer_auth(self.token.secret())
            .json(&json!(roles_to_remove))
            .send()
            .await?;
        Ok(())
    }

    fn get_roles_in_config(user_configs: &Vec<UserConfig>, user: &KeycloakUser) -> Vec<String> {
        user_configs
            .iter()
            .find(|config| config.username == user.username)
            .map(|config| config.roles.clone())
            .unwrap()
    }

    async fn update_users(
        &self,
        users: &Vec<&KeycloakUser>,
        user_configs: &Vec<UserConfig>,
    ) -> anyhow::Result<()> {
        for user in users {
            let user_config = user_configs
                .iter()
                .find(|config| config.username == user.username)
                .unwrap();
            self.update_user(user, user_config).await?;
        }
        Ok(())
    }

    async fn update_user(
        &self,
        user: &KeycloakUser,
        user_config: &UserConfig,
    ) -> anyhow::Result<()> {
        self.reqwest_client
            .put(format!(
                "{}/admin/realms/{}/users/{}",
                self.base_url, self.realm, user.id
            ))
            .bearer_auth(self.token.secret())
            .json(&json!(
                {
                    "firstName": user_config.first_name,
                    "lastName": user_config.last_name,
                    "email": user_config.email,
                    "enabled": user_config.enabled,
                    "username": user_config.username
                }
            ))
            .send()
            .await?;
        Ok(())
    }
}
