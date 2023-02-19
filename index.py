from flask import Flask, request, jsonify
import requests
from flask_cors import CORS
import re
import smtplib
import subprocess
import os
import pymysql
from datetime import datetime, timezone, timedelta
import uuid
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
    services:
      web:
        image: fraunhoferiosb/frost-server:latest
        container_name: {clientID}
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


def create_node_red_new_settings_file(clientID, clientSecret, callbackURL,KEYCLOAK_SERVER_URL,KEYCLOAK_REALM,email):
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
                    authServerURL: "{KEYCLOAK_SERVER_URL}/auth",
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


def replace_settings_file(node_red_storage, clientID, clientSecret, callbackURL,KEYCLOAK_SERVER_URL,KEYCLOAK_REALM,email):
    directory = "/var/lib/docker/volumes/{}/_data".format(node_red_storage)
    new_file_content = create_node_red_new_settings_file(
        clientID, clientSecret, callbackURL,KEYCLOAK_SERVER_URL,KEYCLOAK_REALM,email)

    cmd = f"echo '{new_file_content}' | sudo tee {directory}/settings.js"
    subprocess.run(cmd, shell=True)


def generate_initial_email(status,token,firstName,expiredAt):
    try:
        # Status 1 => User is new and send token for first time
        # Status 2 => User is not new but token is send again
        if status not in [1, 2]:
            return jsonify(success=False, error="Invalid Request"), 500
        
        SMTP_SERVER = os.getenv("SMTP_SERVER")
        SMTP_PORT = int(os.getenv("SMTP_PORT"))
        SMTP_USERNAME = os.getenv("SMTP_USERNAME")
        SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

        message = MIMEText(f"Your token is: {token}")
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "TUM-HEF Account Verification"
        msg['From'] = SMTP_USERNAME
        msg['To'] = "tumhefservicetest@gmail.com"

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
        html = html.format(firstname=firstName, link="http://example.com/verification",expires_at=expiredAt)

        # Attach HTML message to email
        msg.attach(MIMEText(html, 'html'))
     

        # connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, "tumhefservicetest@gmail.com", msg.as_string())

    
    except Exception as err:
        print(err, flush=True)
        return jsonify(success=False, error=str(err)), 500


@app.route('/generate', methods=['POST'])
def process_data():
    token = request.form.get('token')

    if not token:
        return jsonify(success=False,error="Token not obtained"),500

    KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
    KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
    KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
    KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
    KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
    KEYCLOAK_DOMAIN = os.getenv("KEYCLOAK_DOMAIN")
    DATABASE_HOST=os.getenv("DATABASE_HOST")
    DATABASE_USERNAME=os.getenv("DATABASE_USERNAME")
    DATABASE_PASSWORD=os.getenv("DATABASE_PASSWORD")
    DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
    DATABASE_NAME=os.getenv("DATABASE_NAME")

    if not all([KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD, KEYCLOAK_REALM, KEYCLOAK_DOMAIN, DATABASE_HOST, DATABASE_USERNAME, DATABASE_PASSWORD, DATABASE_PORT, DATABASE_NAME]):
        return jsonify(success=False, error="One or more .env variable is missing"), 500

    # Try to connect to the database
    try:
        db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT, user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)
    except pymysql.err.OperationalError as e:
        print(e,flush=True)
        return jsonify(success=False, error="Failed to connect to the database"), 500

    # Check if the connection to the database was successful
    if db is None:
        return jsonify(success=False, error="Failed to connect to the database"), 500

    cursor = db.cursor()

    print(KEYCLOAK_SERVER_URL,flush=True)
    print(KEYCLOAK_CLIENT_ID,flush=True)
    print(KEYCLOAK_USERNAME,flush=True)
    print(KEYCLOAK_PASSWORD,flush=True)
    print(KEYCLOAK_REALM,flush=True)
    print(KEYCLOAK_DOMAIN,flush=True)
    return 'Token processed successfully'

@app.route("/register", methods=["POST"])
def register():
    KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
    KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
    KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
    KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
    KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
    KEYCLOAK_DOMAIN = os.getenv("KEYCLOAK_DOMAIN")

    DATABASE_HOST=os.getenv("DATABASE_HOST")
    DATABASE_USERNAME=os.getenv("DATABASE_USERNAME")
    DATABASE_PASSWORD=os.getenv("DATABASE_PASSWORD")
    DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
    DATABASE_NAME=os.getenv("DATABASE_NAME")

    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

    if not all([KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD, KEYCLOAK_REALM, KEYCLOAK_DOMAIN, DATABASE_HOST, DATABASE_USERNAME, DATABASE_PASSWORD, DATABASE_PORT, DATABASE_NAME,
   SMTP_SERVER, SMTP_PORT,SMTP_USERNAME,SMTP_PASSWORD]):
        return jsonify(success=False, error="One or more .env variable is missing"), 500

    # Try to connect to the database
    try:
        db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT, user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)
    except pymysql.err.OperationalError as e:
        print(e,flush=True)
        return jsonify(success=False, error="Failed to connect to the database"), 500

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
    try:
        commandTUM = ['ldapsearch', '-H', 'ldaps://iauth.tum.de/', '-D', 'cn=TUZEHEZ-KCMAILCHECK,ou=bindDNs,ou=iauth,dc=tum,dc=de', '-b', 'ou=users,ou=data,ou=prod,ou=iauth,dc=tum,dc=de', '-x', '-w', 'HEF@sensorservice2023', f'(&(imAffiliation=member)(imEmailAdressen={email}))']

        resultcommandTUM = subprocess.run(commandTUM, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print(resultcommandTUM.stdout)
        print(resultcommandTUM.stderr)

        if resultcommandTUM.returncode != 0:
            print("Error:", resultcommandTUM.stderr )
            return jsonify(success=False, error=resultcommandTUM.stderr), 500

        tumVerificationResult = verifyTUMresponseString(resultcommandTUM.stdout)

        if(tumVerificationResult is False):
            return jsonify(success=False, error="Your Email is Invalid or does not exist in TUM Database"), 403

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
            try:
                cursor.execute(query, (token, createdAt, email))
                db.commit()
            except Exception as e:
                print(e)
                return jsonify(success=False, error="Failed to update data in database"), 500
            # Send email
            generate_initial_email(status=2,token=token,firstName=firstName,expiredAt=expiredAt)
            return jsonify(success=True, message="Email will be sent again because you are already registered" ), 200

        query = "SELECT * FROM user_registered WHERE email = %s AND isVerified = 1 AND isCompleted = 0"
        cursor.execute(query, (email,))
        result = cursor.fetchall()
        if len(result) > 0:
            return jsonify(success=False, error="You are already verified and registered but not completed" ), 400

        query = "SELECT * FROM user_registered WHERE email = %s AND isVerified = 1 AND isCompleted = 1"
        cursor.execute(query, (email,))
        result = cursor.fetchall()
        if len(result) > 0:
            return jsonify(success=False, error="You are already verified and registered but completed" ), 400

        query = "INSERT INTO user_registered (firstName, lastName, email, token, createdAt) VALUES (%s, %s, %s, %s, %s)"
        try:
            cursor.execute(query, (firstName, lastName, email, token,createdAt))
            db.commit()
        except Exception as e:
            print(e)
            return jsonify(success=False, error="Failed to insert data into database"), 500
        
        # Send email
        generate_initial_email(status=1,token=token,firstName=firstName,expiredAt=expiredAt)
        
        return jsonify(success=True,message="Email Send Successfully"),200

        
        # # Step 1: Get access token
        # token_request = requests.post(
        # f"{KEYCLOAK_SERVER_URL}/auth/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        # data={
        #     "client_id": KEYCLOAK_CLIENT_ID,
        #     "username": KEYCLOAK_USERNAME,
        #     "password": KEYCLOAK_PASSWORD,
        #     "grant_type": "password",
        # },
        # headers={
        #     "Content-Type": "application/x-www-form-urlencoded"
        # }
        # )

        # token_request.raise_for_status()
        # access_token = token_request.json()["access_token"]

        # # Step 2: Create user
        # create_user_request = requests.post(
        #      f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users",
        #     json={
        #         "firstName": firstName,
        #         "lastName": lastName,
        #         "email": email,
        #         "credentials": [
        #             {
        #                 "type": "password",
        #                 "value": password,
        #                 "temporary": False
        #             }
        #         ],
        #         "username": email,
        #         "enabled": True
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # create_user_request.raise_for_status()

        # # Step 3: Send email
        # # create an SMTP object
        # # server = smtplib.SMTP('smtp.gmail.com', 587)

        # # # start the encryption
        # # server.starttls()

        # # # login to your email account
        # # server.login("your_email@gmail.com", "your_password")

        # # # send the email
        # # msg = "Hello, this is a test email."
        # # server.sendmail("your_email@gmail.com", "recipient_email@example.com", msg)

        # # # end the SMTP session
        # # server.quit()

        # # Step 4: GET ALL THE CLIENTS and generate new client id

        # get_clients_request = requests.get(
        #      f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # get_clients_request.raise_for_status()

        # clients = get_clients_request.json()
        # clientIds = [client["clientId"] for client in clients]
        # # Generate new client id
        # new_clientIDNumber = get_max_frost(clientIds)
        # new_clientId = f"frost_{new_clientIDNumber}"

        # # Step 5: Generate new client

        # create_client_request = requests.post(
        #      f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
        #     json={
        #         "clientId": new_clientId,
        #         "enabled": True,
        #         "publicClient": False,  # Access type: confidential
        #         # This is the URL of the Keycloak
        #         "redirectUris": [f"{KEYCLOAK_SERVER_URL}/*"],
        #         "webOrigins": ["*"],
        #         "protocol": "openid-connect",
        #         "bearerOnly": False
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     })

        # # check if request returns 409 status code
        # if create_client_request.status_code == 409:
        #     while create_client_request.status_code == 409:
        #         get_clients_request = requests.get(
        #             f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
        #             headers={
        #                 "Authorization": f"Bearer {access_token}",
        #                 "Content-Type": "application/json"
        #             }
        #         )

        #         get_clients_request.raise_for_status()

        #         clients = get_clients_request.json()
        #         clientIds = [client["clientId"] for client in clients]

        #         new_clientIDNumber = get_max_frost(clientIds)
        #         new_clientId = f"frost_{new_clientIDNumber}"
        #         print(new_clientId, flush=True)

        #         create_client_request = requests.post(
        #               f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
        #             json={
        #                 "clientId": new_clientId,
        #                 "enabled": True,
        #                 # This is the URL of the Keycloak
        #                 "redirectUris": [f"{KEYCLOAK_SERVER_URL}/*"],
        #                 "webOrigins": ["*"],
        #                 "protocol": "openid-connect",
        #                 "bearerOnly": False
        #             },
        #             headers={
        #                 "Authorization": f"Bearer {access_token}",
        #                 "Content-Type": "application/json"
        #             })

        # create_client_request.raise_for_status()

        # # Step 6: Get the client id of the new client
        # get_client_request = requests.get(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients?clientId={new_clientId}",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # get_client_request.raise_for_status()
        # client_id = get_client_request.json()[0]["id"]

        # # STEP 7: Create role for the new client
        # create_role_admin_request = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
        #     json={
        #         "name": "admin"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     })

        # create_role_admin_request.raise_for_status()

        # create_role_read_request = requests.post(
        #      f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
        #     json={
        #         "name": "read"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     })

        # create_role_read_request.raise_for_status()

        # create_role_create_request = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
        #     json={
        #         "name": "create"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     })

        # create_role_create_request.raise_for_status()

        # create_role_delete_request = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
        #     json={
        #         "name": "delete"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     })

        # create_role_delete_request.raise_for_status()

        # # Step 8 : Get the user id of the new user

        # get_user_request = requests.get(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users?username={email}",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # get_user_request.raise_for_status()

        # user_id = get_user_request.json()[0]["id"]

        # # Step 9: GET Role ID where role name is admin, read, create, delete for the new client

        # get_role_new_client_request = requests.get(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # get_role_new_client_request.raise_for_status()

        # role_mapping_request = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_id}",
        #     json=get_role_new_client_request.json(),
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # role_mapping_request.raise_for_status()

        # # Step 10 : GET CLIENT Secret of the new client

        # get_client_secret_request = requests.get(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/client-secret",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # get_client_secret_request.raise_for_status()
        # client_secret = get_client_secret_request.json()["value"]

        # # Step 11 : Generate new YML Template

        # PORT = 6000
        # SECONDPORT = 1890

        # clientPORT = PORT+new_clientIDNumber
        # internalPORT = SECONDPORT+new_clientIDNumber

        # new_yml_template = generateYML(
        #     new_clientId, clientPORT, internalPORT, client_secret)

        # # store the new yml file in yml_files folder

        # print(new_yml_template, flush=True)

        # file_path = os.path.join(
        #     os.getcwd(), "yml_files", f"{new_clientId}.yml")
        # os.makedirs(os.path.dirname(file_path), exist_ok=True)
        # with open(file_path, "w") as f:
        #     f.write(new_yml_template)

        # # Step 12 : Run the new yml file using docker-compose

        # print(new_clientId, flush=True)

        # subprocess_run_frost = subprocess.run(
        # ["sudo","docker-compose","-p", new_clientId, "-f", f"yml_files/{new_clientId}.yml", "up", "-d"])


        # print(subprocess_run_frost, flush=True)

        # # Check if any error occurs when running the new yml file
        # if subprocess_run_frost.returncode != 0:
        #     return jsonify(success=False, error="Error when running the new yml file"), 500


        # # Step 13 : Create a new node-red container for the new client
        
        # PORT_DEFAULT = 20000
        # new_node_red_port = PORT_DEFAULT+new_clientIDNumber
        # node_red_name = f"node_red_{new_clientIDNumber}"
        # node_red_name_storage_name = f"node_red_storage_{new_clientIDNumber}"

        # command_create_node_red_instance = f"sudo docker run -d --init -p {new_node_red_port}:1880 -v {node_red_name_storage_name}:/data --name {node_red_name} nodered/node-red"
        # result_command_create_new_node_instance = subprocess.run(command_create_node_red_instance, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # print(result_command_create_new_node_instance,flush=True)
        # if result_command_create_new_node_instance.returncode != 0:
        #     return jsonify(success=False, error="Error Generating New Node Red Instance"), 500

        # container_node_red_id = get_container_id(node_red_name)

        # print(node_red_name + "WASS ",flush=True)
        # print(container_node_red_id + " WASSS ",flush=True)
        # print(container_node_red_id, flush=True)

        # if (not container_node_red_id):
        #     return jsonify(success=False, error="Error when running the new node-red container, container ID"), 500


        # # Step 14 : Install passport-keycloak-oauth2-oidc in the new node-red container



        # command_node_red_dependency_installation = ["sudo","docker", "exec", container_node_red_id, "bash", "-c",
        #                                             "cd /usr/src/node-red/node_modules && npm install passport-keycloak-oauth2-oidc"]

        # command_red_node = subprocess.run(
        #     command_node_red_dependency_installation)
        
        # print(command_red_node,flush=True)
        
        # if command_red_node.returncode != 0:
        #     return jsonify(success=False, error="Error when installing passport-keycloak-oauth2-oidc"), 500
        # print(command_red_node, flush=True)

        # # Step 15 : Create a new keycloak client in the new node-red

        # # step 15.1 : Get the max client id number in the new node-red and generate the new client id

        # new_clientIDNumber_node_red = new_clientIDNumber
        # new_clientId_node_red = f"node_red_{new_clientIDNumber_node_red}"

        # # Step 15.2 : Create the new client in the new node-red

        # create_client_request_node_red = requests.post(
        #       f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
        #     json={
        #         "clientId": new_clientId_node_red,
        #         "enabled": True,
        #         "publicClient": False,  # Access type: confidential
        #         # This is the URL of the Keycloak
        #         "redirectUris": [f"{KEYCLOAK_SERVER_URL}/*"],
        #         "webOrigins": ["*"],
        #         "protocol": "openid-connect",
        #         "bearerOnly": False
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     })

        # # Step 15.3 check if returns 409 status code

        # if create_client_request_node_red.status_code == 409:
        #     return jsonify(success=False, error="Client in Node Red already exists"), 409

        # create_client_request_node_red.raise_for_status()

        # # Step 15.4 : Get the client id of the new client

        # get_client_request_node_red = requests.get(
        # f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients?clientId={new_clientId_node_red}",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )
        # get_client_request_node_red.raise_for_status()
        # client_id_node_red = get_client_request_node_red.json()[0]["id"]

        # # Step 15.5 : Create role admin, read, create, delete in the new node-red client

        # create_role_admin_node_red = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
        #     json={
        #         "name": "admin"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # create_role_admin_node_red.raise_for_status()

        # create_role_read_node_red = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
        #     json={
        #         "name": "read"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # create_role_read_node_red.raise_for_status()

        # create_role_create_node_red = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
        #     json={
        #         "name": "create"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # create_role_create_node_red.raise_for_status()

        # create_role_delete_node_red = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
        #     json={
        #         "name": "delete"
        #     },
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # create_role_delete_node_red.raise_for_status()

        # # Step 15.6 get the role id of the role admin, read, create, delete

        # get_role_new_client_node_red = requests.get(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )
        # get_role_new_client_node_red.raise_for_status()

        # # Step 15.7 : Do the role mapping for the new user

        # role_mapping_request_node_red = requests.post(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_id_node_red}",
        #     json=get_role_new_client_node_red.json(),
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # role_mapping_request_node_red.raise_for_status()


        # # Step 15.8 : Create the secret

        # get_client_node_red_secret_request = requests.get(
        #     f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/client-secret",
        #     headers={
        #         "Authorization": f"Bearer {access_token}",
        #         "Content-Type": "application/json"
        #     }
        # )

        # get_client_node_red_secret_request.raise_for_status()
        # node_red_client_secret = get_client_node_red_secret_request.json()["value"]


        # print(node_red_client_secret + " SECRET OF NODE RED",flush=True)
        # print(client_id_node_red + " ID OF RED NODE CLIENT",flush=True)

        # callbackURL=f"{KEYCLOAK_DOMAIN}:{new_node_red_port}/auth/strategy/callback"

        # print(new_clientId_node_red + " TEST ", flush=True)

        # replace_settings_file(node_red_name_storage_name,
        #                       new_clientId_node_red, node_red_client_secret, callbackURL,KEYCLOAK_SERVER_URL,KEYCLOAK_REALM,email)

        # # Step 15.9 : Restart the node-red container

        # restart_node_red_container = subprocess.run(
        #     f"sudo docker restart {container_node_red_id}", shell=True, check=True)
        
        # print(restart_node_red_container,flush=True)

        # if restart_node_red_container.returncode != 0:
        #     return jsonify(success=False, error="Server Error by restarting container"), 500


        # return jsonify(success=True, message="User created successfully")

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
