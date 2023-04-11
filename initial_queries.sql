CREATE DATABASE IF NOT EXISTS tumservices;
use tumservices;
CREATE TABLE user_registered (
  ID int AUTO_INCREMENT PRIMARY KEY,
  firstName varchar(255) NOT NULL,
  lastName varchar(255) NOT NULL,
  email varchar(255) NOT NULL,
  token varchar(255) NOT NULL,
  isVerified boolean DEFAULT false,
	keycloak_user_creation boolean DEFAULT false,
  keycloak_generate_client boolean DEFAULT false,
  keycloak_create_roles_for_client boolean DEFAULT false,
  keycloak_role_mapping boolean DEFAULT false,
  yml_genereration boolean DEFAULT false,
  frost_yml_execution boolean DEFAULT false,
  node_red_command_execution boolean DEFAULT false,
  node_red_install_libaries boolean DEFAULT false,
  node_red_keycloak_generate_new_client boolean DEFAULT false,
  node_red_keycloak_generate_roles boolean DEFAULT false,
  node_red_keycloak_role_mapping boolean DEFAULT false,
  node_red_replace_settings boolean DEFAULT false,
  node_red_restart_container boolean DEFAULT false,
  isCompleted boolean DEFAULT false,
  createdAt timestamp DEFAULT CURRENT_TIMESTAMP,
  completedAt timestamp DEFAULT NULL
);

CREATE TABLE services (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  frost_port_one INT,
  frost_port_two INT,
  node_red_port INT,
  FOREIGN KEY (user_id) REFERENCES user_registered(ID)
);