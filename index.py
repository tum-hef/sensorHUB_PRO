from flask import Flask, request, jsonify, render_template
import requests
from flask_cors import CORS
import re
import smtplib
import subprocess
import os
import pymysql
from datetime import datetime, timezone, timedelta
import uuid
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
app = Flask(__name__)
app.config['DEBUG'] = True
CORS(app)


def get_container_id(container_name):
    command = f"sudo docker ps --filter name={container_name} --format '{{{{.ID}}}}'"
    output = subprocess.run(command, shell=True, capture_output=True)
    if output.returncode != 0:
        return jsonify(success=False, error="Error getting the container ID"), 500
    return output.stdout.decode().strip()


def get_max_frost(arr):
    frost_nums = [x for x in arr if x.startswith("frost_") and x[6:].isdigit()]
    if not frost_nums:
        return 0
    max_num = max(frost_nums, key=lambda x: int(x.split("_")[1]))
    return int(max_num.split("_")[1]) + 1


def get_max_node_red(arr):
    node_red_nums = [x for x in arr if x.startswith(
        "node_red_") and x[10:].isdigit()]
    if not node_red_nums:
        return 0
    max_num = max(node_red_nums, key=lambda x: int(x.split("_")[1]))
    return int(max_num.split("_")[1]) + 1


def generateYML(clientID, port, secondPort, clientSecret, KEYCLOAK_REALM, ROOT_URL):
    yml_template = """
    version: '3'
    services:
      web:
        image: fraunhoferiosb/frost-server:2.0
        container_name: {clientID}
        environment:
          - serviceRootUrl={ROOT_URL}:{port}/FROST-Server
          - http_cors_enable=true
          - http_cors_allowed.origins=*
          - persistence_db_driver=org.postgresql.Driver
          - persistence_db_url=jdbc:postgresql://database:5432/sensorthings
          - persistence_db_username=sensorthings
          - persistence_db_password=ChangeMe
          - persistence_autoUpdateDatabase=true
          - persistence_alwaysOrderbyId=true
          - auth.provider=de.fraunhofer.iosb.ilt.frostserver.auth.keycloak.KeycloakAuthProvider
          - auth.keycloakConfigUrl={ROOT_URL}:8080/auth/realms/{KEYCLOAK_REALM}/clients-registrations/install/{clientID}
          - auth.keycloakConfigSecret={clientSecret}
        ports:
          - {port}:8080
          - {secondPort}:1883
        depends_on:
          - database
        restart: always
      database:
        image: postgis/postgis:11-2.5-alpine
        container_name: {clientID}_db
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
    return yml_template.format(clientID=clientID, secondPort=secondPort,  port=port, clientSecret=clientSecret, KEYCLOAK_REALM=KEYCLOAK_REALM, ROOT_URL=ROOT_URL)


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


def create_node_red_new_settings_file(clientID, clientSecret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL):
    new_file_content = f"""
    module.exports = {{
        flowFile: "flows.json",
        flowFilePretty: true,
        adminAuth: {{
            type:"strategy",
            strategy: {{
                name: "keycloak",
                label: "Sign in",
                icon:"fa-lock",
                strategy: require("passport-keycloak-oauth2-oidc").Strategy,
                options: {{
                    clientID: "{clientID}",
                    realm: "{KEYCLOAK_REALM}",
                    publicClient: "false",
                    clientSecret: "{clientSecret}",
                    sslRequired: "external",
                    authServerURL: "{ROOT_URL}:8080/auth",
                    callbackURL: "{callbackURL}",
                }},
                verify: function(token, tokenSecret, profile, done) {{
                    done(null, profile);
                }}
            }},
            users: [
               {{ username: "{email}",permissions: ["*"]}}
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


def replace_settings_file(node_red_storage, clientID, clientSecret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL):
    directory = "/var/lib/docker/volumes/{}/_data".format(node_red_storage)
    new_file_content = create_node_red_new_settings_file(
        clientID, clientSecret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL)

    cmd = f"echo '{new_file_content}' | sudo tee {directory}/settings.js"
    subprocess.run(cmd, shell=True)


def generate_email(status, token, firstName, expiredAt):
    try:
        # Status 1 => User is new and send token for first time
        # Status 2 => User is not new but token is send again
        if status not in [1, 2]:
            return jsonify(success=False, error="Invalid Request"), 500

        SMTP_SERVER = os.getenv("SMTP_SERVER")
        SMTP_PORT = int(os.getenv("SMTP_PORT"))
        SMTP_USERNAME = os.getenv("SMTP_USERNAME")
        SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

        SERVER_URL = os.getenv("SERVER_URL")

        message = MIMEText(f"Your token is: {token}")
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "TUM-HEF Account Verification"
        msg['From'] = SMTP_USERNAME
        msg['To'] = "tumhefservicetest@gmail.com"

        URL = f'{SERVER_URL}/validate?token={token}'

        if status == 1:
            # Create HTML message for Status 1
            html = """\
            <html>
            <head></head>
            <body style="text-align: center;">
                <h2>Hi {firstname},</h2>
                <p>Thank you for registering,</p>
                <p>Please click <a href="{link}">here</a> to verify your account and to generate services for you. This link will expire on {expires_at}.</p>
                <p>Thank you,</p>
            </body>
            </html>
            """
        if status == 2:
            # Create HTML message for Status 2
            html = """\
            <html>
            <head></head>
            <body style="text-align: center;">
                <h2>Hi {firstname},</h2>
                <p>Thank you for registering, we have created a new valid link for you</p>
                <p>Please click <a href="{link}">here</a> to verify your account and to generate services for you. This link will expire on {expires_at}.</p>
                <p>Thank you,</p>
            </body>
            </html>
            """
        # Replace placeholders with actual values
        html = html.format(firstname=firstName, link=URL, expires_at=expiredAt)

        # Attach HTML message to email
        msg.attach(MIMEText(html, 'html'))

        # connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(
                SMTP_USERNAME, "tumhefservicetest@gmail.com", msg.as_string())

    except Exception as err:
        print(err, flush=True)
        return jsonify(success=False, error=str(err)), 500


def generate_success_email(firstName, email):
    try:

        SMTP_SERVER = os.getenv("SMTP_SERVER")
        SMTP_PORT = int(os.getenv("SMTP_PORT"))
        SMTP_USERNAME = os.getenv("SMTP_USERNAME")
        SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = "TUM-HEF Success"
        msg['From'] = SMTP_USERNAME
        msg['To'] = "tumhefservicetest@gmail.com"  # email of the user

        html = """\
        <html>
        <head></head>
        <body style="text-align: center;">
            <h2>Mr. {firstname}, thank you for registering!</h2>
            <p>Your account has been successfully created.</p>
            <p>You can access your account now.</p>
            <p>Thank you!</p>
        </body>
        </html>
        """
        # Replace placeholders with actual values
        html = html.format(firstname=firstName)

        # Attach HTML message to email
        msg.attach(MIMEText(html, 'html'))

        # connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            # Here should be the user's email
            server.sendmail(
                SMTP_USERNAME, "tumhefservicetest@gmail.com", msg.as_string())

    except Exception as err:
        print(err, flush=True)
        return jsonify(success=False, error=str(err)), 500


@app.route('/validate')
def my_page():
    try:
        token = request.args.get('token')
        KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
        KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
        KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
        KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
        KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")

        DATABASE_HOST = os.getenv("DATABASE_HOST")
        DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
        DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
        DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
        DATABASE_NAME = os.getenv("DATABASE_NAME")

        ROOT_URL = os.getenv("ROOT_URL")

        # Check if there is no Token passed in the URL as Query Parameter
        if token is None:
            error = 'Token is not set'
            return render_template('token.html', error=error)


        # Try to connect to the database
        try:
            db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                                 user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)
        except pymysql.err.OperationalError as e:
            print(e, flush=True)
            return render_template('token.html', error="Failed to connect to the database")

        if db is None:
            return render_template('token.html', error="Failed to connect to the database")

        cursor = db.cursor()

        # Query to check if token is valid
        query = "SELECT * FROM user_registered WHERE token = %s and ((isVerified = 0 AND isCompleted = 0) OR (isVerified = 1 AND isCompleted = 0))"
        print(query, flush=True)
        cursor.execute(query, (token,))
        result = cursor.fetchall()

        print(result, flush=True)

        # Check if token is invalid or user's registration is already completed
        if len(result) == 0:
            return render_template('token.html', error="Token is Invalid or you have already created an account.")

        firstName = result[0][1]
        lastName = result[0][2]
        email = result[0][3]
        createdAt = result[0][20]
        password = "1"

        # Checking if token is valid based on the time that was created

        # Set the timezone to Munich
        munich_tz = timezone(timedelta(hours=1))

        # Get the current time in Munich
        now = datetime.now(munich_tz)

        # Convert createdAt to a UTC datetime object and replace the timezone with UTC
        created_at = createdAt.replace(
            tzinfo=munich_tz).astimezone(timezone.utc)

        # Convert the createdAt datetime to Munich timezone
        created_at_munich = created_at.astimezone(munich_tz)

        # Calculate the time difference between createdAt and now
        time_diff = now - created_at_munich

        # Check if the time difference is more than 24 hours
        if time_diff > timedelta(hours=24):
            print("Error: createdAt is more than 24 hours ago.", flush=True)
            return render_template('token.html', error="Token is no more valid, try to register again in order to generate a new one.")

        # Verifing the user
        query = "UPDATE user_registered SET isVerified = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 1: Get access token
        token_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
            data={
                "client_id": KEYCLOAK_CLIENT_ID,
                "username": KEYCLOAK_USERNAME,
                "password": KEYCLOAK_PASSWORD,
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
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users",
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

        # Successful creation of the keycloak user
        query = "UPDATE user_registered SET keycloak_user_creation = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        get_clients_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
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

        PORT = 6000
        SECONDPORT = 1890

        clientPORT = PORT+new_clientIDNumber
        internalPORT = SECONDPORT+new_clientIDNumber

        create_client_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
            json={
                "clientId": new_clientId,
                "enabled": True,
                "serviceAccountsEnabled": True,
                "publicClient": False,  # Access type: confidential
                "authorizationServicesEnabled": True,
                "redirectUris": [f"{ROOT_URL}:{clientPORT}/FROST-Server/*"],
                "webOrigins": [f"{ROOT_URL}:{clientPORT}"],
                "protocol": "openid-connect",
                "bearerOnly": False,
                "adminUrl": f"{ROOT_URL}:{clientPORT}/FROST-Server",
                "rootUrl": f"{ROOT_URL}:{clientPORT}/FROST-Server"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        # check if request returns 409 status code
        if create_client_request.status_code == 409:
            while create_client_request.status_code == 409:
                get_clients_request = requests.get(
                    f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
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

                clientPORT = PORT+new_clientIDNumber
                internalPORT = SECONDPORT+new_clientIDNumber

                create_client_request = requests.post(
                    f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
                    json={
                        "clientId": new_clientId,
                        "enabled": True,
                        "serviceAccountsEnabled": True,
                        "publicClient": False,  # Access type: confidential
                        "authorizationServicesEnabled": True,
                        "redirectUris": [f"{ROOT_URL}:{clientPORT}/FROST-Server/*"],
                        "webOrigins": [f"{ROOT_URL}:{clientPORT}"],
                        "protocol": "openid-connect",
                        "bearerOnly": False,
                        "adminUrl": f"{ROOT_URL}:{clientPORT}/FROST-Server",
                        "rootUrl": f"{ROOT_URL}:{clientPORT}/FROST-Server"
                    },
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json"
                    })

        create_client_request.raise_for_status()

        # Successful creation of the keycloak client
        query = "UPDATE user_registered SET keycloak_generate_client = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 6: Get the client id of the new client
        get_client_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients?clientId={new_clientId}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_request.raise_for_status()
        client_id = get_client_request.json()[0]["id"]

        # STEP 7: Create role for the new client
        create_role_admin_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "admin"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_admin_request.raise_for_status()

        create_role_read_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "read"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_read_request.raise_for_status()

        create_role_create_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "create"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_create_request.raise_for_status()

        create_role_delete_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "delete"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        create_role_delete_request.raise_for_status()

        # Successful creation of the keycloak roles
        query = "UPDATE user_registered SET keycloak_create_roles_for_client = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 8 : Get the user id of the new user

        get_user_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users?username={email}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_user_request.raise_for_status()

        user_id = get_user_request.json()[0]["id"]

        # Step 9: GET Role ID where role name is admin, read, create, delete for the new client

        get_role_new_client_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_role_new_client_request.raise_for_status()

        role_mapping_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_id}",
            json=get_role_new_client_request.json(),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        role_mapping_request.raise_for_status()

        # Successful creation of the keycloak role mapping
        query = "UPDATE user_registered SET keycloak_role_mapping = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 10 : GET CLIENT Secret of the new client

        get_client_secret_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/client-secret",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_secret_request.raise_for_status()
        client_secret = get_client_secret_request.json()["value"]

        # Step 11 : Generate new YML Template

        new_yml_template = generateYML(
            new_clientId, clientPORT, internalPORT, client_secret, KEYCLOAK_REALM, ROOT_URL)

        # Successful of generating the YML file
        query = "UPDATE user_registered SET yml_genereration = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # store the new yml file in yml_files folder

        print(new_yml_template, flush=True)

        file_path = os.path.join(
            os.getcwd(), "yml_files", f"{new_clientId}.yml")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(new_yml_template)

        # Step 12 : Run the new yml file using docker-compose

        print(new_clientId, flush=True)

        subprocess_run_frost = subprocess.run(
            ["sudo", "docker-compose", "-p", new_clientId, "-f", f"yml_files/{new_clientId}.yml", "up", "-d"])

        print(subprocess_run_frost, flush=True)

        # Check if any error occurs when running the new yml file
        if subprocess_run_frost.returncode != 0:
            return render_template('token.html', error="Error when running the new yml file")

        # Successful of executing Frost file
        query = "UPDATE user_registered SET frost_yml_execution = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # return render_template('token.html', token="Account created successfully")

        # Step 13 : Create a new node-red container for the new client

        PORT_DEFAULT = 20000
        new_node_red_port = PORT_DEFAULT+new_clientIDNumber
        node_red_name = f"node_red_{new_clientIDNumber}"
        node_red_name_storage_name = f"node_red_storage_{new_clientIDNumber}"

        command_create_node_red_instance = f"sudo docker run -d --init -p {new_node_red_port}:1880 -v {node_red_name_storage_name}:/data --name {node_red_name} nodered/node-red"
        result_command_create_new_node_instance = subprocess.run(
            command_create_node_red_instance, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        print(result_command_create_new_node_instance, flush=True)
        if result_command_create_new_node_instance.returncode != 0:
            # return jsonify(success=False, error="Error Generating New Node Red Instance"), 500
            return render_template('token.html', error="Error Generating New Node Red Instance")

        # Successful node red command execution
        query = "UPDATE user_registered SET node_red_command_execution = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        container_node_red_id = get_container_id(node_red_name)

        print(node_red_name + "WASS ", flush=True)
        print(container_node_red_id + " WASSS ", flush=True)
        print(container_node_red_id, flush=True)

        if (not container_node_red_id):
            # return jsonify(success=False, error="Error when running the new node-red container, container ID"), 500
            return render_template('token.html', error="Error when running the new node-red container, container ID")

        # Step 14 : Install passport-keycloak-oauth2-oidc in the new node-red container

        command_node_red_dependency_installation = ["sudo", "docker", "exec", container_node_red_id, "bash", "-c",
                                                    "cd /usr/src/node-red/node_modules && npm install passport-keycloak-oauth2-oidc"]

        command_red_node = subprocess.run(
            command_node_red_dependency_installation)

        print(command_red_node, flush=True)

        if command_red_node.returncode != 0:
            # return jsonify(success=False, error="Error when installing passport-keycloak-oauth2-oidc"), 500
            return render_template('token.html', error="Error when installing passport-keycloak-oauth2-oidc")
        print(command_red_node, flush=True)

        # Successful node red libary installation
        query = "UPDATE user_registered SET node_red_install_libaries = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 15 : Create a new keycloak client in the new node-red
        # step 15.1 : Get the max client id number in the new node-red and generate the new client id

        new_clientIDNumber_node_red = new_clientIDNumber
        new_clientId_node_red = f"node_red_{new_clientIDNumber_node_red}"

        # Step 15.2 : Create the new client in the new node-red

        print(f"{ROOT_URL} {new_node_red_port} DOMAIN PRINT", flush=True)

        create_client_request_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
            json={
                "clientId": new_clientId_node_red,
                "enabled": True,
                "publicClient": False,  # Access type: confidential
                # This is the URL of the Keycloak
                "webOrigins": ["*"],
                "protocol": "openid-connect",
                "bearerOnly": False,
                "serviceAccountsEnabled": True,
                "authorizationServicesEnabled": True,
                "redirectUris": [f"{ROOT_URL}:{new_node_red_port}/*"],
                "webOrigins": [f"{ROOT_URL}:{new_node_red_port}"],
                "adminUrl": f"{ROOT_URL}:{new_node_red_port}",
                "rootUrl": f"{ROOT_URL}:{new_node_red_port}",
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })

        # Step 15.3 check if returns 409 status code

        if create_client_request_node_red.status_code == 409:
            # return jsonify(success=False, error="Client in Node Red already exists"), 409
            return render_template('token.html', error="Client in Node Red already exists")

        create_client_request_node_red.raise_for_status()

        # Successful keycloak client generation for keycloak
        query = "UPDATE user_registered SET node_red_keycloak_generate_new_client = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 15.4 : Get the client id of the new client

        get_client_request_node_red = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients?clientId={new_clientId_node_red}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        get_client_request_node_red.raise_for_status()
        client_id_node_red = get_client_request_node_red.json()[0]["id"]

        # Step 15.5 : Create role admin, read, create, delete in the new node-red client

        create_role_admin_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
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
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
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
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
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
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
            json={
                "name": "delete"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_role_delete_node_red.raise_for_status()

        # Successful keycloak roles generation for node red
        query = "UPDATE user_registered SET node_red_keycloak_generate_roles = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 15.6 get the role id of the role admin, read, create, delete

        get_role_new_client_node_red = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        get_role_new_client_node_red.raise_for_status()

        # Step 15.7 : Do the role mapping for the new user

        role_mapping_request_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_id_node_red}",
            json=get_role_new_client_node_red.json(),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        role_mapping_request_node_red.raise_for_status()

        # Successful keycloak roles mapping generation for node red
        query = "UPDATE user_registered SET node_red_keycloak_role_mapping = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 15.8 : Create the secret

        get_client_node_red_secret_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/client-secret",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_node_red_secret_request.raise_for_status()
        node_red_client_secret = get_client_node_red_secret_request.json()[
            "value"]

        print(node_red_client_secret + " SECRET OF NODE RED", flush=True)
        print(client_id_node_red + " ID OF RED NODE CLIENT", flush=True)

        callbackURL = f"{ROOT_URL}:{new_node_red_port}/auth/strategy/callback"

        print(new_clientId_node_red + " TEST ", flush=True)

        replace_settings_file(node_red_name_storage_name,
                              new_clientId_node_red, node_red_client_secret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL)

        # Successful settings.js update
        query = "UPDATE user_registered SET node_red_replace_settings = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 15.9 : Restart the node-red container

        restart_node_red_container = subprocess.run(
            f"sudo docker restart {container_node_red_id}", shell=True, check=True)

        print(restart_node_red_container, flush=True)

        if restart_node_red_container.returncode != 0:
            # return jsonify(success=False, error="Server Error by restarting container"), 500
            return render_template('token.html', error="Server Error by restarting container")

        # Successful restart of node red instance
        query = "UPDATE user_registered SET node_red_restart_container = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Get current timestamp as a datetime object
        now = datetime.now(timezone(timedelta(hours=1)))

        # Making isCompleted true
        query = "UPDATE user_registered SET isCompleted = 1, completedAt = %s WHERE token = %s;"
        print(query, flush=True)

        # Execute the query, passing the current timestamp as a datetime object
        cursor.execute(query, (now, token))
        db.commit()

        # Send confirmation mail
        generate_success_email(firstName, email)

        return render_template('token.html', token="Account created successfully")

    except requests.exceptions.HTTPError as err:
        print(err)
        if err.response.status_code == 409:
            errorText = err.response.json()["errorMessage"]
            # return jsonify(success=False, error=errorText), 409
            return render_template('token.html', error=errorText)
        else:
            # return jsonify(success=False, error="Server Error"), 500
            return render_template('token.html', error="Server Error")
    except Exception as err:
        print(err, flush=True)
        tb = traceback.format_exception(type(err), err, err.__traceback__)
        error_message = tb[-1].strip()  # Get the last line of the traceback
        # Get the line number from the second-to-last line of the traceback
        line_number = tb[-2].split(", ")[1].strip()
        print("***********************************************", flush=True)
        print(error_message, flush=True)
        print("***********************************************", flush=True)
        print(line_number, flush=True)

        # tb = err.__traceback__
        # # get the line number of the error
        # line_num = tb.tb_lineno
        # # print the error message and line number
        # print(f"Error on line {line_num}: {err}",flush=True)

        # return jsonify(success=False, error=str(err)), 500
        return render_template('token.html', error=str(err))

   


@app.route("/register", methods=["POST"])
def register():
    try:
        KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
        KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
        KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
        KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
        KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")


        DATABASE_HOST = os.getenv("DATABASE_HOST")
        DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
        DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
        DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
        DATABASE_NAME = os.getenv("DATABASE_NAME")

        SMTP_SERVER = os.getenv("SMTP_SERVER")
        SMTP_PORT = int(os.getenv("SMTP_PORT"))
        SMTP_USERNAME = os.getenv("SMTP_USERNAME")
        SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

        if not all([KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD, KEYCLOAK_REALM, DATABASE_HOST, DATABASE_USERNAME, DATABASE_PASSWORD, DATABASE_PORT, DATABASE_NAME,
                    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD]):
            return jsonify(success=False, error="One or more .env variable is missing"), 500

        # Try to connect to the database
        db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                             user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)

        # Check if the connection to the database was successful
        if db is None:
            return jsonify(success=False, error="Failed to connect to the database"), 500

        cursor = db.cursor()

        firstName = request.json.get("firstName")
        lastName = request.json.get("lastName")
        email = request.json.get("email")
        username = request.json.get("username")
        password = request.json.get("password")

        if not all([firstName, lastName, email, username, password]):
            return jsonify(success=False, error="Inputs are missing"), 400
        commandTUM = ['ldapsearch', '-H', 'ldaps://iauth.tum.de/', '-D', 'cn=TUZEHEZ-KCMAILCHECK,ou=bindDNs,ou=iauth,dc=tum,dc=de', '-b',
                      'ou=users,ou=data,ou=prod,ou=iauth,dc=tum,dc=de', '-x', '-w', 'HEF@sensorservice2023', f'(&(imAffiliation=member)(imEmailAdressen={email}))']

        print("TEST2", flush=True)
        # tumVerificationResult = verifyTUMresponseString(
        #     resultcommandTUM.stdout)

        resultcommandTUM = subprocess.run(
            commandTUM, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print(resultcommandTUM.stdout)
        print(resultcommandTUM.stderr)

        # if resultcommandTUM.returncode != 0:
        # print("Error:", resultcommandTUM.stderr)
        # return jsonify(success=False, error=resultcommandTUM.stderr), 500

        # tumVerificationResult = verifyTUMresponseString(
        #     resultcommandTUM.stdout)

        # if(tumVerificationResult is False):
        #     return jsonify(success=False, error="Your Email is Invalid or does not exist in TUM Database"), 403

        # Get current timestamp
        now_utc2 = datetime.now(timezone(timedelta(hours=1)))
        createdAt = now_utc2.strftime('%Y-%m-%d %H:%M:%S')

        # Calculate expiration timestamp (24 hours after createdAt)
        expiration = now_utc2 + timedelta(hours=24)
        expiredAt = expiration.strftime('%d %B %Y %H:%M')

        # Generate Token
        token = str(uuid.uuid4())

        query = "SELECT * FROM user_registered WHERE email = %s AND isVerified = 0 AND isCompleted = 0"
        cursor.execute(query, (email,))
        result = cursor.fetchall()
        if len(result) > 0:
            # Update token and the time createdAt
            query = "UPDATE user_registered SET token = %s, createdAt = %s WHERE email = %s"
            cursor.execute(query, (token, createdAt, email))
            db.commit()

            # Send email
            generate_email(status=2, token=token,
                           firstName=firstName, expiredAt=expiredAt)
            return jsonify(success=True, message="Email will be sent again because you are already registered"), 200

        query = "SELECT * FROM user_registered WHERE email = %s AND isVerified = 1 AND isCompleted = 0"
        cursor.execute(query, (email,))
        result = cursor.fetchall()
        if len(result) > 0:
            generate_email(status=2, token=token,
                           firstName=firstName, expiredAt=expiredAt)
            return jsonify(success=True, message="Email will be sent again because you are not completed"), 200

        query = "SELECT * FROM user_registered WHERE email = %s AND isVerified = 1 AND isCompleted = 1"
        cursor.execute(query, (email,))
        result = cursor.fetchall()
        if len(result) > 0:
            return jsonify(success=False, error="You are already verified and registered in our system"), 400

        query = "INSERT INTO user_registered (firstName, lastName, email, token, createdAt) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(
            query, (firstName, lastName, email, token, createdAt))
        db.commit()

        # Send email
        generate_email(status=1, token=token,
                       firstName=firstName, expiredAt=expiredAt)

        return jsonify(success=True, message="Email Send Successfully"), 200

    except pymysql.err.OperationalError as e:
        print(e, flush=True)
        return jsonify(success=False, error="Failed to connect to the database"), 500

    except requests.exceptions.HTTPError as err:
        print(err, flush=True)

        if err.response.status_code == 409:
            errorText = err.response.json()["errorMessage"]
            return jsonify(success=False, error=errorText), 409
        else:
            return jsonify(success=False, error="Server Error"), 500
    except Exception as err:
        print(err, flush=True)
        return jsonify(success=False, error=str(err)), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="4500")
