use clap::Parser;
use log::error;
use log::info;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::AccessToken;
use oauth2::ClientId;
use oauth2::TokenResponse;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_with::skip_serializing_none;
use tokio;

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
    about = "A simple CLI to setup Keycloak Users in a realm",
    name = "keycloak-user-cli",
    color = clap::ColorChoice::Always
)]
struct Args {
    #[clap(short, long)]
    config: String,
    #[clap(short, long)]
    users: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct User {
    id: String,
    username: String,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    #[serde(default = "true_bool")]
    enabled: bool,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct Config {
    keycloak_url: String,
    auth_realm: String,
    auth_username: String,
    auth_password: String,
    auth_client_id: String,
    #[serde(default = "false_bool")]
    delete_users: bool,
    realm: String,
}

#[skip_serializing_none]
#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct UserConfig {
    username: String,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    roles: Vec<String>,
    #[serde(default = "true_bool")]
    enabled: bool,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
struct Role {
    id: String,
    name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //Set Log Level to Info
    env_logger::builder().filter_level(log::LevelFilter::Info).init();

    let args: Args = Args::parse();
    let config = std::fs::read_to_string(args.config)?;
    let config: Config = serde_json::from_str(&config)?;

    let user_configs = std::fs::read_to_string(args.users)?;
    let user_configs: Vec<UserConfig> = serde_json::from_str(&user_configs)?;

    let keycloak_client = KeycloakClient::new(
        config.keycloak_url,
        config.realm,
        config.auth_username,
        config.auth_password,
    )
    .await?;
    let users = keycloak_client.get_all_users().await?;
    // Split users into those in the config and those not in the config
    let users_in_config_and_in_keycloak: Vec<User> = users
        .into_iter()
        .filter(|user| {
            user_configs
                .iter()
                .any(|config| config.username == user.username)
        })
        .collect();

    // Create users in Keycloak that are in the config but not in Keycloak
    let users_to_create: Vec<&UserConfig> = user_configs
        .iter()
        .filter(|config| {
            !users_in_config_and_in_keycloak
                .iter()
                .any(|user| user.username == config.username)
        })
        .collect();
    keycloak_client.create_users(users_to_create).await?;

    // Get all Users in Keycloak
    let users = keycloak_client.get_all_users().await?;
    // Split users into those in the config and those not in the config
    let (users_in_config_and_in_keycloak, users_not_in_config_but_in_keycloak): (
        Vec<User>,
        Vec<User>,
    ) = users.into_iter().partition(|user| {
        user_configs
            .iter()
            .any(|config| config.username == user.username)
    });
    // Update users in Keycloak that are in the config and in Keycloak
    keycloak_client
        .update_users(&users_in_config_and_in_keycloak, &user_configs)
        .await?;

    // Update Roles of users in Keycloak that are in the config and in Keycloak
    keycloak_client
        .update_roles(&user_configs, &users_in_config_and_in_keycloak)
        .await?;

    // Delete/Disable users in Keycloak that are not in the config but in Keycloak
    // ,depending on the config
    if config.delete_users {
        info!("Deleting users that are not in the config");
        keycloak_client
            .delete_users(&users_not_in_config_but_in_keycloak)
            .await?;
    } else {
        info!("Disabling users that are not in the config");
        keycloak_client
            .disable_users(&users_not_in_config_but_in_keycloak)
            .await?
    }
    Ok(())
}

struct KeycloakClient {
    base_url: String,
    realm: String,
    token: AccessToken,
    reqwest_client: reqwest::Client,
}
impl KeycloakClient {
    async fn new(
        base_url: String,
        realm: String,
        user: String,
        password: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let oauth_client = BasicClient::new(
            ClientId::new("admin-cli".to_string()),
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
        users: Vec<&UserConfig>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

    async fn get_all_users(&self) -> Result<Vec<User>, Box<dyn std::error::Error>> {
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
            .json::<Vec<User>>()
            .await?)
    }

    async fn disable_users(&self, users: &Vec<User>) -> Result<(), Box<dyn std::error::Error>> {
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

    async fn delete_users(&self, users: &Vec<User>) -> Result<(), Box<dyn std::error::Error>> {
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

    async fn get_all_realm_roles(&self) -> Result<Vec<Role>, Box<dyn std::error::Error>> {
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
            .json::<Vec<Role>>()
            .await?)
    }

    async fn get_realm_roles(&self, user: &User) -> Result<Vec<Role>, Box<dyn std::error::Error>> {
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
            .json::<Vec<Role>>()
            .await?)
    }

    fn roles_to_add(
        config_roles: &Vec<String>,
        keycloak_roles: &Vec<Role>,
        existing_roles: &Vec<Role>,
    ) -> Vec<Role> {
        keycloak_roles
            .iter()
            .filter(|role| config_roles.contains(&role.name))
            .filter(|role| !existing_roles.contains(role))
            .cloned()
            .collect()
    }

    fn roles_to_remove(config_roles: &Vec<String>, keycloak_roles: &Vec<Role>) -> Vec<Role> {
        keycloak_roles
            .iter()
            .filter(|role| !config_roles.contains(&role.name))
            .cloned()
            .collect()
    }

    async fn update_roles(
        &self,
        user_configs: &Vec<UserConfig>,
        users_keycloak: &Vec<User>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        roles_to_add: &Vec<Role>,
        roles_to_remove: &Vec<Role>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

    fn get_roles_in_config(user_configs: &Vec<UserConfig>, user: &User) -> Vec<String> {
        user_configs
            .iter()
            .find(|config| config.username == user.username)
            .map(|config| config.roles.clone())
            .unwrap()
    }

    async fn update_users(
        &self,
        users: &Vec<User>,
        user_configs: &Vec<UserConfig>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        user: &User,
        user_config: &UserConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
