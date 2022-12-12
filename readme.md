# Keycloak User
This is a simple user management application for Keycloak. It allows you to configure users and their roles in a file.
This Application will then create/update the users and assign them the roles in Keycloak. It will also delete/disable users that are not in the configuration file.

## Usage
### Configuration
The configuration file is a simple json file. It contains the following fields:
- `keycloak_url`: The url of the keycloak server
- `auth_realm`: The realm to authenticate against (usually master)
- `auth_username`: The username to authenticate with (usually admin)
- `auth_password`: The password to authenticate with
- `auth_client_id`: The client id to authenticate with (usually admin-cli)
- `delete_users`: If set to true, users that are not in the configuration file will be deleted
- `realm`: The realm to manage users in

### User Configuration
The user configuration is a simple json file. It contains the following fields:
- `users`: An array of users to create/update
  - `username`: The username of the user
  - `email`: The email of the user (optional)
  - `enabled`: Whether the user is enabled (default: true, optional)
  - `firstName`: The first name of the user (optional)
  - `lastName`: The last name of the user (optional)
  - `roles`: An array of roles to assign to the user

### Running
To run the application, simply execute the following command:

```bash
keycloak-user -c <CONFIG_FILE> -u <USER_FILE>
```

## Building
To build the application, simply execute the following command:

```bash
cargo build --release
```

## License
This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.