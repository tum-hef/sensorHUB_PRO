from flask import Flask, request, jsonify
import requests
from flask_cors import CORS
import re
import smtplib
import subprocess
import os

app = Flask(__name__)
app.config['DEBUG'] = True
CORS(app)


def get_container_id(container_name):
    command = f"docker ps --filter name={container_name} --format '{{{{.ID}}}}'"
    output = subprocess.run(command, shell=True, capture_output=True)
    return output.stdout.decode().strip()


def get_max_frost(arr):
    frost_nums = list(filter(lambda x: x.startswith("frost_"), arr))
    if not frost_nums:
        return 0
    max_num = max(frost_nums, key=lambda x: int(x.split("_")[1]))
    return int(max_num.split("_")[1]) + 1


def get_max_node_red(arr):
    frost_nums = list(filter(lambda x: x.startswith("node_red_"), arr))
    if not frost_nums:
        return 0
    max_num = max(frost_nums, key=lambda x: int(x.split("_")[1]))
    return int(max_num.split("_")[1]) + 1


def generateYML(clientID, port, secondPort, clientSecret):
    yml_template = """
    version: '3'
    name: {clientID}
    services:
      web:
        image: fraunhoferiosb/frost-server:latest
        environment:
          - serviceRootUrl=http://138.246.225.0:{port}/FROST-Server
          - http_cors_enable=true
          - http_cors_allowed.origins=*
          - persistence_db_driver=org.postgresql.Driver
          - persistence_db_url=jdbc:postgresql://database:5432/sensorthings
          - persistence_db_username=sensorthings
          - persistence_db_password=ChangeMe
          - persistence_autoUpdateDatabase=true
          - persistence_alwaysOrderbyId=true
          - auth.provider=de.fraunhofer.iosb.ilt.frostserver.auth.keycloak.KeycloakAuthProvider
          - auth.keycloakConfigUrl=http://tuzehez-hefiot.srv.mwn.de:8080/auth/realms/master/clients-registrations/install/{clientID}
          - auth.keycloakConfigSecret={clientSecret}
        ports:
          - {port}:8080
          - {secondPort}:1883
        depends_on:
          - database
        restart: always
      database:
        image: postgis/postgis:11-2.5-alpine
        environment:
          - POSTGRES_DB=sensorthings
          - POSTGRES_USER=sensorthings
          - POSTGRES_PASSWORD=ChangeMe
        volumes:
          - postgis_volume:/var/lib/postgresql/data
        restart: always
    volumes:
        postgis_volume:
    """
    return yml_template.format(clientID=clientID, secondPort=secondPort,  port=port, clientSecret=clientSecret)


def verifyTUMresponseString(response):
    if (not response):
        return jsonify(success=False, error="Error in TUM Verification Response"), 500
    match = re.search(r'cn=(\w+),', response)
    if match:
        print(match.group(1), flush=True)
        return True
    else:
        print("No match found.", flush=True)
        return False


def create_node_red_new_settings_file(clientID, clientSecret, callbackURL):
    new_file_content = f"""
    module.exports = {{
        flowFile: 'flows.json',
        flowFilePretty: true,
        adminAuth: {{
            type:"strategy",
            strategy: {{
                name: "keycloak",
                label: 'Sign in',
                icon:"fa-lock",
                strategy: require("passport-keycloak-oauth2-oidc").Strategy,
                options: {{
                    clientID: "{clientID}",
                    realm: 'master',
                    publicClient: "false",
                    clientSecret: "{clientSecret}",
                    sslRequired: "external",
                    authServerURL: "http://tuzehez-hefiot.srv.mwn.de:8080/auth",
                    callbackURL: "{callbackURL}",
                }},
                verify: function(token, tokenSecret, profile, done) {{
                    done(null, profile);
                }}
            }},
            users: [
               {{ username: "node-red-user1",permissions: ["*"]}}
            ]
        }},
        uiPort: process.env.PORT || 1880,
        diagnostics: {{
            enabled: true,
            ui: true,
        }},
        runtimeState: {{
            enabled: false,
            ui: false,
        }},
        logging: {{
            console: {{
                level: "info",
                metrics: false,
                audit: false
            }}
        }},
        exportGlobalContextKeys: false,
        externalModules: {{
        }},
        editorTheme: {{
            palette: {{
              
            }},

            projects: {{
                enabled: false,
                workflow: {{
                    mode: "manual"
                }}
            }},
            codeEditor: {{
                lib: "monaco",
                options: {{    
                }}
            }},
        }},
        functionExternalModules: true,
        functionGlobalContext: {{
        }},
        debugMaxLength: 1000,
        mqttReconnectTime: 15000,
        serialReconnectTime: 15000,
    }}
    """
    return new_file_content


def replace_settings_file(node_red_storage, clientID, clientSecret, callbackURL):
    directory = "\\\\wsl$\\docker-desktop-data\\data\\docker\\volumes\\{}\\_data".format(
        node_red_storage)

    os.chdir(directory)

    new_file_content = create_node_red_new_settings_file(
        clientID, clientSecret, callbackURL)

    with open("settings.js", "w") as f:
        f.write(new_file_content)


@app.route("/register", methods=["POST"])
def register():
    firstName = request.json.get("firstName")
    lastName = request.json.get("lastName")
    email = request.json.get("email")
    username = request.json.get("username")
    password = request.json.get("password")

    if not all([firstName, lastName, email, username, password]):
        return jsonify(success=False, error="Inputs are missing"), 400
    try:
        # Step 1: Get access token
        token_request = requests.post(
            "http://localhost:8080/auth/realms/keycloak-react-auth/protocol/openid-connect/token",
            data={
                "client_id": "react",
                "username": "parid",
                "password": "1",
                "grant_type": "password",
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )

        token_request.raise_for_status()
        access_token = token_request.json()["access_token"]

        # Step 2: Create user
        create_user_request = requests.post(
            "http://localhost:8080/auth/admin/realms/keycloak-react-auth/users",
            json={
                "firstName": firstName,
                "lastName": lastName,
                "email": email,
                "credentials": [
                    {
                        "type": "password",
                        "value": password,
                        "temporary": False
                    }
                ],
                "username": email,
                "enabled": True
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_user_request.raise_for_status()

        # Step 3: Send email
        # create an SMTP object
        # server = smtplib.SMTP('smtp.gmail.com', 587)

        # # start the encryption
        # server.starttls()

        # # login to your email account
        # server.login("your_email@gmail.com", "your_password")

        # # send the email
        # msg = "Hello, this is a test email."
        # server.sendmail("your_email@gmail.com", "recipient_email@example.com", msg)

        # # end the SMTP session
        # server.quit()

        # Step 4: GET ALL THE CLIENTS and generate new client id

        get_clients_request = requests.get(
            "http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_clients_request.raise_for_status()

        clients = get_clients_request.json()
        clientIds = [client["clientId"] for client in clients]
        # Generate new client id
        new_clientIDNumber = get_max_frost(clientIds)
        new_clientId = f"frost_{new_clientIDNumber}"

        # Step 5: Generate new client

        create_client_request = requests.post(
            "http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients",
            json={
                "clientId": new_clientId,
                "enabled": True,
                "publicClient": False,  # Access type: confidential
                # This is the URL of the Keycloak
                "redirectUris": ["http://localhost:8080/*"],
                "webOrigins": ["*"],
                "protocol": "openid-connect",
                "bearerOnly": False
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        # check if request returns 409 status code
        if create_client_request.status_code == 409:
            while create_client_request.status_code == 409:
                get_clients_request = requests.get(
                    "http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json"
                    }
                )

                get_clients_request.raise_for_status()

                clients = get_clients_request.json()
                clientIds = [client["clientId"] for client in clients]

                new_clientIDNumber = get_max_frost(clientIds)
                new_clientId = f"frost_{new_clientIDNumber}"
                print(new_clientId, flush=True)

                create_client_request = requests.post(
                    "http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients",
                    json={
                        "clientId": new_clientId,
                        "enabled": True,
                        # This is the URL of the Keycloak
                        "redirectUris": ["http://localhost:8080/*"],
                        "webOrigins": ["*"],
                        "protocol": "openid-connect",
                        "bearerOnly": False
                    },
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json"
                    })

        create_client_request.raise_for_status()

        # Step 6: Get the client id of the new client
        get_client_request = requests.get(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients?clientId={new_clientId}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_request.raise_for_status()
        client_id = get_client_request.json()[0]["id"]

        # STEP 7: Create role for the new client
        create_role_admin_request = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id}/roles",
            json={
                "name": "admin"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_admin_request.raise_for_status()

        create_role_read_request = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id}/roles",
            json={
                "name": "read"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_read_request.raise_for_status()

        create_role_create_request = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id}/roles",
            json={
                "name": "create"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_create_request.raise_for_status()

        create_role_delete_request = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id}/roles",
            json={
                "name": "delete"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_delete_request.raise_for_status()

        # Step 8 : Get the user id of the new user

        get_user_request = requests.get(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/users?username={email}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_user_request.raise_for_status()

        user_id = get_user_request.json()[0]["id"]

        # Step 9: GET Role ID where role name is admin, read, create, delete for the new client

        get_role_new_client_request = requests.get(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id}/roles",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_role_new_client_request.raise_for_status()

        role_mapping_request = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/users/{user_id}/role-mappings/clients/{client_id}",
            json=get_role_new_client_request.json(),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        role_mapping_request.raise_for_status()

        # Step 10 : GET CLIENT Secret of the new client

        get_client_secret_request = requests.get(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id}/client-secret",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_secret_request.raise_for_status()
        client_secret = get_client_secret_request.json()["value"]

        # Step 11 : Generate new YML Template

        PORT = 6000
        SECONDPORT = 1890

        clientPORT = PORT+new_clientIDNumber
        internalPORT = SECONDPORT+new_clientIDNumber

        new_yml_template = generateYML(
            new_clientId, clientPORT, internalPORT, client_secret)

        # store the new yml file in yml_files folder

        print(new_yml_template, flush=True)

        file_path = os.path.join(
            os.getcwd(), "yml_files", f"{new_clientId}.yml")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(new_yml_template)

        # Step 12 : Run the new yml file using docker-compose

        subprocess_run_frost = subprocess.run(
            ["docker-compose", "-f", f"yml_files/{new_clientId}.yml", "up", "-d"])

        print(subprocess_run_frost, flush=True)

        # Check if any error occurs when running the new yml file
        if subprocess_run_frost.returncode != 0:
            return jsonify(success=False, error="Error when running the new yml file"), 500

        # Step 13 : Create a new node-red container for the new client

        PORT_DEFAULT = 20000
        new_node_red_port = PORT_DEFAULT+new_clientIDNumber
        node_red_name = f"node_red_{new_clientIDNumber}"
        node_red_name_storage_name = f"node_red_storage_{new_clientIDNumber}"

        command_create_node_red_instance = f"docker run -d --init -p {new_node_red_port}:1880 -v {node_red_name_storage_name}:/data --name {node_red_name} nodered/node-red"
        os.system(command_create_node_red_instance)

        container_node_red_id = get_container_id(node_red_name)
        container_node_red_id = container_node_red_id[1:-1]
        print(container_node_red_id, flush=True)

        if (not container_node_red_id):
            return jsonify(success=False, error="Error when running the new node-red container, container ID"), 500

        # Step 14 : Create new node-red container and specify the data_storage-directory accordingly

        # command_node_red_creating_node_red_container_specifing_data_storage = ["docker", "run", "-d", "--restart", "always", "-p",
        #                                                                        f"{new_node_red_port}:1880", "-v", f"{node_red_name_storage_name}:/data", "--name", f"{node_red_name}", "nodered/node-red"]

        # command_red_node_specifying_data_storage = subprocess.run(
        #     command_node_red_creating_node_red_container_specifing_data_storage)
        # if command_red_node_specifying_data_storage.returncode != 0:
        #     return jsonify(success=False, error="Error when running the new node-red container"), 500
        # print(command_red_node_specifying_data_storage, flush=True)

        # Step 15 : Install passport-keycloak-oauth2-oidc in the new node-red container

        command_node_red_dependency_installation = ["docker", "exec", container_node_red_id, "bash", "-c",
                                                    "cd /usr/src/node-red/node_modules && npm install passport-keycloak-oauth2-oidc"]

        command_red_node = subprocess.run(
            command_node_red_dependency_installation)
        if command_red_node.returncode != 0:
            return jsonify(success=False, error="Error when installing passport-keycloak-oauth2-oidc"), 500
        print(command_red_node, flush=True)

        # Step 16 : Create a new keycloak client in the new node-red

        # step 16.1 : Get the max client id number in the new node-red and generate the new client id

        new_clientIDNumber_node_red = new_clientIDNumber
        new_clientId_node_red = f"node_red_{new_clientIDNumber_node_red}"

        # Step 16.2 : Create the new client in the new node-red

        create_client_request_node_red = requests.post(
            "http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients",
            json={
                "clientId": new_clientId_node_red,
                "enabled": True,
                "publicClient": False,  # Access type: confidential
                # This is the URL of the Keycloak
                "redirectUris": ["http://localhost:8080/*"],
                "webOrigins": ["*"],
                "protocol": "openid-connect",
                "bearerOnly": False
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        # Step 16.3 check if returns 409 status code

        if create_client_request_node_red.status_code == 409:
            return jsonify(success=False, error="Client in Node Red already exists"), 409

        create_client_request_node_red.raise_for_status()

        # Step 16.4 : Get the client id of the new client

        get_client_request_node_red = requests.get(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients?clientId={new_clientId_node_red}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        get_client_request_node_red.raise_for_status()
        client_id_node_red = get_client_request_node_red.json()[0]["id"]

        # Step 16.5 : Create role admin, read, create, delete in the new node-red client

        create_role_admin_node_red = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id_node_red}/roles",
            json={
                "name": "admin"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_role_admin_node_red.raise_for_status()

        create_role_read_node_red = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id_node_red}/roles",
            json={
                "name": "read"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_role_read_node_red.raise_for_status()

        create_role_create_node_red = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id_node_red}/roles",
            json={
                "name": "create"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_role_create_node_red.raise_for_status()

        create_role_delete_node_red = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id_node_red}/roles",
            json={
                "name": "delete"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_role_delete_node_red.raise_for_status()

        # Step 16.6 get the role id of the role admin, read, create, delete

        get_role_new_client_node_red = requests.get(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id_node_red}/roles",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        get_role_new_client_node_red.raise_for_status()

        # Step 16.7 : Do the role mapping for the new user

        role_mapping_request_node_red = requests.post(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/users/{user_id}/role-mappings/clients/{client_id_node_red}",
            json=get_role_new_client_node_red.json(),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        role_mapping_request_node_red.raise_for_status()

    # call the function with the correct path to the folder
        # replace_settings_js(
        #     '\\\\wsl$\\docker-desktop-data\\data\\docker\\volumes\\node_red_storage_1\\_data')

        # Step 16.8 : Create the secret

        get_client_node_red_secret_request = requests.get(
            f"http://localhost:8080/auth/admin/realms/keycloak-react-auth/clients/{client_id}/client-secret",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_node_red_secret_request.raise_for_status()
        node_red_client_secret = get_client_secret_request.json()["value"]

        replace_settings_file(node_red_name_storage_name,
                              client_id_node_red, node_red_client_secret, "callbackURL")

        # Step 16.9 : Restart the node-red container

        restart_node_red_container = subprocess.run(
            f"docker restart {container_node_red_id}", shell=True, check=True)

        if restart_node_red_container.returncode != 0:
            return jsonify(success=False, error="Server Error by restarting container"), 500

        try:
            subprocess.run(
                f"cd \\\\wsl$\\docker-desktop-data\\data\\docker\\volumes\\{node_red_name_storage_name}", shell=True, check=True)
            subprocess.run("dir", shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(e.stderr)

        return jsonify(success=True, message="User created successfully")

    except requests.exceptions.HTTPError as err:
        print(err)

        if err.response.status_code == 409:
            errorText = err.response.json()["errorMessage"]
            return jsonify(success=False, error=errorText), 409
        else:
            return jsonify(success=False, error="Server Error"), 500
    except Exception as err:
        print(err, flush=True)
        return jsonify(success=False, error=str(err)), 500


if __name__ == '__main__':
    app.run(port=4500)
