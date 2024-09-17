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
import re
import json
from time import sleep
from threading import Thread
app = Flask(__name__)
app.config['DEBUG'] = True
CORS(app)


def update_service_column(service_id, column_name, new_value, cursor, db):
    try:
        # Execute the query to update the specified column for the given service_id
        query = f"UPDATE services SET {column_name} = %s WHERE id = %s;"
        cursor.execute(query, (new_value, service_id))
        db.commit()

        # If the update was successful, return True; otherwise return False
        if cursor.rowcount > 0:
            return True
        else:
            return False
    except pymysql.Error as error:
        print("Error:", error)


def get_max_column_value(column_name, cursor, db):
    try:
        # Execute the query to retrieve the maximum value of the column
        query = f"SELECT MAX({column_name}) FROM services;"
        cursor.execute(query)

        # Get the maximum value from the query result
        max_value = cursor.fetchone()[0]

        # Return the maximum value
        return max_value

    except pymysql.Error as error:
        print("Error:", error)


def check_variable_exists_in_ports(variable, cursor, db):
    try:
        # Execute the query to check if the variable exists in any of the three columns
        query = f"SELECT * FROM services WHERE frost_port_one = %s OR frost_port_two = %s OR node_red_port = %s LIMIT 1;"
        cursor.execute(query, (variable, variable, variable))

        # If the variable exists in any of the three columns, return True; otherwise return False
        if cursor.fetchone():
            return True
        else:
            return False
    except pymysql.Error as error:
        print("Error:", error)


def check_column_data_exists(column_name, cursor, db):
    try:
        # Execute the query to check if any data exists in the specified column
        query = f"SELECT {column_name} FROM services WHERE {column_name} IS NOT NULL LIMIT 1;"

        cursor.execute(query)

        # If any data exists in the column, return True; otherwise return False
        if cursor.fetchone():
            return True
        else:
            return False
    except pymysql.Error as error:
        print("Error:", error)


def get_container_id(container_name):
    command = f"docker ps --filter name={container_name} --format '{{{{.ID}}}}'"
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


def generateYML(clientID, port, secondPort, clientSecret, KEYCLOAK_REALM, ROOT_URL,KEYCLOAK_SERVER_URL,frost_newURL):
    yml_template = """
    version: '3'
    services:
      web:
        image: fraunhoferiosb/frost-server:2.0
        container_name: {clientID}
        environment:
          - serviceRootUrl={frost_newURL}/FROST-Server
          - http_cors_enable=true
          - http_cors_allowed.origins=*
          - persistence_db_driver=org.postgresql.Driver
          - persistence_db_url=jdbc:postgresql://database:5432/sensorthings
          - persistence_db_username=sensorthings
          - persistence_db_password=ChangeMe
          - persistence_autoUpdateDatabase=true
          - persistence_alwaysOrderbyId=true
          - auth.provider=de.fraunhofer.iosb.ilt.frostserver.auth.keycloak.KeycloakAuthProvider
          - auth.keycloakConfigUrl={KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/clients-registrations/install/{clientID}
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
    return yml_template.format(clientID=clientID, secondPort=secondPort,  port=port, clientSecret=clientSecret, KEYCLOAK_REALM=KEYCLOAK_REALM, ROOT_URL=ROOT_URL,KEYCLOAK_SERVER_URL=KEYCLOAK_SERVER_URL,frost_newURL=frost_newURL)


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


def create_node_red_new_settings_file(clientID, clientSecret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL,):
    print(clientID, clientSecret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL)
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
                    scope: "openid profile email",
                    authServerURL: "{KEYCLOAK_SERVER_URL}",
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




def replace_settings_file(node_red_storage, clientID, clientSecret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL,nodered_newURL):
    # Construct the mountpoint using the provided volume name
    mountpoint = subprocess.check_output(f"docker volume inspect {node_red_storage} --format='{{{{.Mountpoint}}}}'", shell=True, text=True).strip()

    # Construct the full path to the settings file
    settings_file_path = f"{mountpoint}/settings.js"

    new_file_content = create_node_red_new_settings_file(
        clientID, clientSecret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL,)

    # Write new_file_content to the settings file
    with open(settings_file_path, "w") as settings_file:
        settings_file.write(new_file_content)

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
                <p>Please click <a href={link}>here</a> (alternatively directly use following link: {link}) to verify your account and to generate services for you. This link will expire on {expires_at}.</p>
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
                <p>Please click <a href={link}>here</a> (alternatively directly use following link: {link}) to verify your account and to generate services for you. This link will expire on {expires_at}.</p>
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
            <p>Initial password is:  </p> <b> TUM@HEF@2023 </b>
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

def create_dns_and_generate_ssl(domain, email, dns_script_path="/root/dns_script/nsupdate_hef_dynamic.sh", webroot_path="/var/www/html"):
    """
    Runs the DNS update script with the given domain using sudo, generates a Let's Encrypt SSL certificate
    using the webroot method, and returns paths to the generated certificate and key.

    Parameters:
    domain (str): The domain to be updated and for which the SSL certificate will be generated.
    email (str): Email address for notifications from Let's Encrypt.
    dns_script_path (str): Path to the DNS update script.
    webroot_path (str): Webroot path used by Certbot for domain validation.

    Returns:
    dict: A dictionary containing status and paths to the certificate and key, or error messages.
    """
    # Clean up the domain string
    domain = domain.replace("https://", "").replace("http://", "")
    print(f"Cleaned domain: {domain}")

    # Prepare the command to run the DNS update script with sudo
    command = ['sudo', 'bash', dns_script_path, domain]
    print(f"Running command: {' '.join(command)}")

    try:
       
        # Run the DNS update script with sudo
        dns_update_result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        print(f"DNS Update STDOUT: {dns_update_result.stdout}")
        print(f"DNS Update STDERR: {dns_update_result.stderr}")
        
        subprocess.run(['docker', 'stop', 'nginx'], check=True)

        # Wait for DNS propagation (if necessary)
        # Note: This is a placeholder. You may need to implement a wait/check for DNS propagation.
        sleep(30)
        command = [
            'certbot', 'certonly',
            '--standalone',
            '--domain', domain,
            '--email', 'your-email@example.com',  # Replace with your email
            '--agree-tos',
            '--non-interactive'
        ]
        print("letsenrcypt command",command)
        # Run the certbot command
        result = subprocess.run(command, capture_output=True, text=True)
        subprocess.run(['docker', 'start', 'nginx'], check=True)
        # Check if the command was successful
        if result.returncode == 0:
            print(f"Certbot ran successfully for domain: {domain}")
        else:
            print(f"Certbot failed. Error: {result.stderr}")
    except Exception as e:
        print(f"An error occurred: {e}")
def append_https_server_block(domain, port, nginx_conf_path="/root/keycloak-setup/nginx.conf"):
    # Remove scheme if present in the domain
    domain = domain.replace("https://", "").replace("http://", "")
    
    # Define the HTTPS server block
    https_server_block = f"""
server {{
    listen 443 ssl;
    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';

    location / {{
        proxy_pass http://138.246.225.192:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
    """

    # Ensure the Nginx configuration path is an absolute path
    nginx_conf_path = os.path.abspath(nginx_conf_path)

    # Read the existing nginx.conf from the host system
    if os.path.exists(nginx_conf_path):
        with open(nginx_conf_path, "r") as file:
            existing_conf = file.read()
    else:
        print(f"Configuration file {nginx_conf_path} does not exist.")
        return

    # Check if the server block already exists
    if f"server_name {domain};" in existing_conf:
        print(f"HTTPS server block for {domain} already exists in {nginx_conf_path}")
        return

    # Split the existing configuration into parts
    # Ensure there are no extra closing braces at the end
    existing_conf = existing_conf.strip()
    if existing_conf.endswith('}'):
        existing_conf = existing_conf[:-1].strip()
    
    # Prepare the updated configuration
    updated_conf = existing_conf + "\n" + https_server_block + "\n}\n"

    # Write the updated configuration back to the file
    with open(nginx_conf_path, "w") as file:
        file.write(updated_conf)

    # Test the Nginx configuration inside the Docker container
    try:
        # Convert port to string before passing to subprocess
        port_str = str(port)
        
        # Allow the port in the firewall
        subprocess.run(['sudo', 'ufw', 'allow', port_str], check=True)
        print("Firewall rule added for port", port_str)
        
        # Test Nginx configuration
        subprocess.run([
            "docker", "exec", "nginx",  # Replace with your actual container name
            "nginx", "-t"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error testing Nginx configuration: {e}")
        return

    # Reload Nginx to apply the changes inside the Docker container
    try:
        subprocess.run([
            "docker", "exec", "nginx",  # Replace with your actual container name
            "nginx", "-s", "reload"
        ], check=True)
        print("Nginx reloaded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error reloading Nginx configuration: {e}")
        return

    print(f"HTTPS server block for {domain} appended to {nginx_conf_path}")

def run_tasks_sequentially(frost_newURL, nodered_newURL, clientPORT, new_node_red_port):
    # Run tasks sequentially
    create_dns_and_generate_ssl(frost_newURL, "tumhefservicetest@gmail.com")
    create_dns_and_generate_ssl(nodered_newURL, "tumhefservicetest@gmail.com")
    append_https_server_block(frost_newURL, clientPORT)
    append_https_server_block(nodered_newURL, new_node_red_port)

@app.route("/frost-server", methods=["GET"])
def frost_server():
    email = request.args.get("email")
    if not email:
        # email parameter not received, handle the error here
        return jsonify({"success": False, "message": "Email parameter not received"})
    if "@" not in email or "." not in email:
        # email parameter not in correct format, handle the error here
        return jsonify({"success": False, "message": "Email parameter not in correct format"})

    DATABASE_HOST = os.getenv("DATABASE_HOST")
    DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
    DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
    DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
    DATABASE_NAME = os.getenv("DATABASE_NAME")
    # Try to connect to the database
    db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                         user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)

    # Check if the connection to the database was successful
    
    if db is None:
        return jsonify(success=False, error="Failed to connect to the database"), 500

    cursor = db.cursor()

    # Query to get the node_red_port based on email
    query = "SELECT s.frost_port_one FROM services s JOIN user_registered ur ON ur.id = s.user_id WHERE ur.email = %s LIMIT 1"
    cursor.execute(query, (email,))
    result = cursor.fetchall()

    if len(result) == 0:
        return jsonify({"success": False, "message": "Does Not Exist"}), 404

    PORT = result[0][0]
    if PORT is None:
        return jsonify(success=False, error="Error occurred "), 500

    return jsonify({"success": True, "PORT": PORT})

@app.route("/test", methods=["GET"])
def test():
    return jsonify({"success": True})
        

@app.route("/frost-clients", methods=["GET"])
def frost_client():
    user_id = request.args.get('user_id')
    KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
    KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
    KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
    KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
    KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")

    try:
        # Step 1: Get access token
        token_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
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

        try:
            # Step 2: Fetch the list of clients for the user
            clients_request = requests.get(
                f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
            )
            clients_request.raise_for_status()
            clients = clients_request.json()

            return jsonify({"success": True, "clients": clients})

        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/node-red", methods=["GET"])
def node_red():
    email = request.args.get("email")
    if not email:
        # email parameter not received, handle the error here
        return jsonify({"success": False, "message": "Email parameter not received"})
    if "@" not in email or "." not in email:
        # email parameter not in correct format, handle the error here
        return jsonify({"success": False, "message": "Email parameter not in correct format"})

    DATABASE_HOST = os.getenv("DATABASE_HOST")
    DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
    DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
    DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
    DATABASE_NAME = os.getenv("DATABASE_NAME")
    # Try to connect to the database
    db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                         user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)

    # Check if the connection to the database was successful
    if db is None:
        return jsonify(success=False, error="Failed to connect to the database"), 500

    cursor = db.cursor()

    # Query to get the node_red_port based on email
    query = "SELECT s.node_red_port FROM services s JOIN user_registered ur ON ur.id = s.user_id WHERE ur.email = %s LIMIT 1"
    cursor.execute(query, (email,))
    result = cursor.fetchall()

    if len(result) == 0:
        return jsonify({"success": False, "message": "Does Not Exist"}), 404

    PORT = result[0][0]
    if PORT is None:
        return jsonify(success=False, error="Error occurred "), 500

    return jsonify({"success": True, "PORT": PORT})


@app.route('/get_clients', methods=["GET"])
def get_cllients():
    try:
        user_id = request.args.get('user_id')

        if (user_id == None):
            return jsonify({"success": False, "message": "user_id not provided"}), 400

        KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
        KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
        KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
        KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
        KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")

        # Step 1: Get access token
        token_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
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

        # Step 2: Get group where user is part

        group_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/groups",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        group_request.raise_for_status()
        groups_json = group_request.json()
        groups = []

        if (len(groups_json) == 0):
            return jsonify({"success": False, "message": "User does not belong to any group"}), 404

        for group in groups_json:
            group_request = requests.get(
                f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/groups/{group['id']}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
            )
            group_request.raise_for_status()

            group_json = group_request.json()

            # print inside an objcet the id and inside that object the attributes
            print(group_json['id'])
            print(group_json['attributes'])

            object = {
                "id": group_json['id'],
                "attributes": group_json['attributes']
            }

            groups.append(object)
            # print(json.dumps(group_json, indent=4, sort_keys=True))

        print(groups)

        # for each group, get attributes
        # Step 3: For each group, get the clients by doing the role mapping

        clients_name = []
        clients = []

        for group in groups:
            clients_request = requests.get(
                f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/groups/{group['id']}/role-mappings",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
            )
            clients_request.raise_for_status()
            clients_json = clients_request.json()

            # # print(json.dumps(clients_json, indent=4, sort_keys=True))

            # print(clients_json)

            # for client in clients_json['clientMappings']:
            #     clients_name.append(client)

            # # Step 3: For each client, get the the root url

            # for client in clients_name:
            #     client_request = requests.get(
            #         f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients?clientId={client}",
            #         headers={
            #             "Authorization": f"Bearer {access_token}",
            #             "Content-Type": "application/json"
            #         }
            #     )

            #     client_request.raise_for_status()
            #     client_data = client_request.json()

            #     for client in client_data:
            #         clients.append({
            #             'root_url': client['rootUrl'],
            #             'client_id': client['clientId']
            #         })

        return jsonify({"success": True, "groups": groups}), 200

    except Exception as e:
        tb = traceback.format_exception(
            type(e), e, e.__traceback__)
        error_message = tb[-1].strip()  # Get the last line of the traceback
        # Get the line number from the second-to-last line of the traceback
        line_number = tb[-2].split(", ")[1].strip()
        print("***********************************************", flush=True)
        print(error_message, flush=True)
        print("***********************************************", flush=True)
        print(line_number, flush=True)
        print("***********************************************", flush=True)
        print(tb, flush=True)
        return jsonify({"success": False, "error": str(e)}), 500


@ app.route('/validate', methods=["GET"])
def validate_user():
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
        
        SERVER_IP=os.getenv("SERVER_IP")
        NODERED_URL=os.getenv("NODERED_URL")
        FROST_URL=os.getenv("FROST_URL")
        

        ROOT_URL = os.getenv("ROOT_URL")

        GROUP_ID_RANDOM_NAME_GENERATOR = uuid.uuid4().hex

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
        createdAt = result[0][24]
        password = "TUM@HEF@2023"

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
        print("Step1 before  {KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token") 
        sleep(5)
        token_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
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
        print("token_request",token_request.json())
        token_request.raise_for_status()
        access_token = token_request.json()["access_token"]

        # Step 2: Create user
        create_user_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users",
            json={
                "firstName": firstName,
                "lastName": lastName,
                "email": email,
                "credentials": [
                    {
                        "type": "password",
                        "value": password,
                        "temporary": True
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
        print("step2")

        # Successful creation of the keycloak user
        query = "UPDATE user_registered SET keycloak_user_creation = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        get_clients_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        get_clients_request.raise_for_status()
        print("step3")
        # Get ID of the new user
        query = "SELECT id FROM user_registered where email = %s;"
        print(query, flush=True)
        cursor.execute(query, (email,))
        db.commit()

        # Retrieve the user ID value from the cursor
        result = cursor.fetchone()
        user_id = result[0]

        # Print the user ID value
        print("User ID:", user_id, flush=True)

        query = "INSERT INTO services (user_id) VALUES (%s);"

        cursor.execute(query, (user_id,))
        db.commit()
        print("Data inserted successfully into service table for user ID:", user_id)

        # Select the id column from the service table where the user_id matches the specified user_id
        query = "SELECT id FROM services WHERE user_id = %s;"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        service_id = result[0]

        print(service_id, flush=True)

        FORST_DEFAULT_PORT = 6000
        FROST_SECOND_DEFAULT_PORT = 1890

        PORT_DEFAULT_NODE_RED = 20000

        frost_port_one_check = check_column_data_exists(
            "frost_port_one", cursor=cursor, db=db)

        print("TEST1", flush=True)
        print(frost_port_one_check, flush=True)

        if frost_port_one_check:
            print("TEST2", flush=True)
            new_frost_port_one = get_max_column_value(
                "frost_port_one", cursor, db) + 1
            collision_exist = check_variable_exists_in_ports(
                new_frost_port_one, cursor, db)
            print("TEST3", flush=True)
            while (collision_exist):
                new_frost_port_one += 1
                collision_exist = collision_exist = check_variable_exists_in_ports(
                    new_frost_port_one, cursor, db)
                print("TEST4", flush=True)

            clientPORT = new_frost_port_one
            update_service_column(
                service_id, "frost_port_one", clientPORT, cursor, db)
            print("TEST5", flush=True)

            # Port Frost two check
            frost_port_two_check = check_column_data_exists(
                "frost_port_two", cursor=cursor, db=db)
            print("TEST6", flush=True)

            if frost_port_two_check:
                print("TEST7", flush=True)
                new_frost_port_two = get_max_column_value(
                    "frost_port_two", cursor, db) + 1
                collision_exist = check_variable_exists_in_ports(
                    new_frost_port_two, cursor, db)

                while (collision_exist):
                    print("TEST8", flush=True)
                    new_frost_port_two += 1
                    collision_exist = collision_exist = check_variable_exists_in_ports(
                        new_frost_port_two, cursor, db)
                    print("TEST9", flush=True)

                internalPORT = new_frost_port_two
                update_service_column(
                    service_id, "frost_port_two", internalPORT, cursor, db)
                print("TEST10", flush=True)

            else:
                print("TEST11", flush=True)
                new_frost_port_two = FROST_SECOND_DEFAULT_PORT + service_id
                internalPORT = new_frost_port_two
                update_service_column(
                    service_id, "frost_port_two", internalPORT, cursor, db)

        else:
            print("TEST12", flush=True)
            new_frost_port_one = FORST_DEFAULT_PORT + service_id
            clientPORT = new_frost_port_one
            print("TEST12", flush=True)

            update_service_column(
                service_id, "frost_port_one", clientPORT, cursor, db)

            print("TEST13", flush=True)

            new_frost_port_two = FROST_SECOND_DEFAULT_PORT + service_id
            internalPORT = new_frost_port_two
            print("TEST14", flush=True)
            update_service_column(
                service_id, "frost_port_two", internalPORT, cursor, db)
            print("TEST15", flush=True)

        print(clientPORT, flush=True)
        print(internalPORT, flush=True)

        # Store the Group ID On Database
        update_service_column(
            service_id, "group_id", GROUP_ID_RANDOM_NAME_GENERATOR, cursor, db)

        # Step 5: Generate new client

        new_clientId = f"frost_{clientPORT}"
        frost_newURL =  f"https://{clientPORT}-{FROST_URL[len('https://'):]}"

        create_client_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients",
            json={
                "clientId": new_clientId,
                "enabled": True,
                "serviceAccountsEnabled": True,
                "publicClient": False,  # Access type: confidential
                "authorizationServicesEnabled": True,
                "redirectUris": [f"{frost_newURL}/FROST-Server/v1.0","*"],
                "webOrigins": ["*"],
                "protocol": "openid-connect",
                "bearerOnly": False,
                "adminUrl": f"{frost_newURL}/FROST-Server",
                "rootUrl": f"{frost_newURL}/FROST-Server",
                "attributes":{
                    "exclude.issuer.from.auth.response": "true",
                }
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
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients?clientId={new_clientId}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_request.raise_for_status()
        client_id = get_client_request.json()[0]["id"]

        # STEP 7: Create role for the new client
        create_role_admin_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "admin"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })
        print("admin")

        create_role_admin_request.raise_for_status()

        create_role_read_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "read"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })
        print("read")
        create_role_read_request.raise_for_status()

        # Update role for the new client

        create_role_update_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "update"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })
        print("update")
        create_role_update_request.raise_for_status()

        create_role_create_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "create"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })
        print("create")

        create_role_create_request.raise_for_status()

        create_role_delete_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            json={
                "name": "delete"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            })
        print("delete")

        create_role_delete_request.raise_for_status()

        # Successful creation of the keycloak roles
        query = "UPDATE user_registered SET keycloak_create_roles_for_client = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 8 : Get the user id of the new user

        get_user_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users?username={email}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_user_request.raise_for_status()

        user_id = get_user_request.json()[0]["id"]

        # Step 9: GET Role ID where role name is admin, read, create, delete for the new client

        get_role_new_client_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_role_new_client_request.raise_for_status()

        role_mapping_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_id}",
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

        # Step 9.1: Create group
        create_group_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/groups",
            json={
                "name": GROUP_ID_RANDOM_NAME_GENERATOR,
                "attributes": {
                    "group_type": ["individual"],
                    "group_name": [email]
                }
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        create_group_request.raise_for_status()

        print("*****GROUP NAME ******", flush=True)
        print(GROUP_ID_RANDOM_NAME_GENERATOR, flush=True)
        print("*****GROUP NAME ******", flush=True)

        query = "UPDATE user_registered SET group_creation = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 9.2 Get The ID Of Group
        get_group_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/groups?search={GROUP_ID_RANDOM_NAME_GENERATOR}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_group_request.raise_for_status()
        group_id = get_group_request.json()[0]["id"]

        print("************", flush=True)
        print(group_id, flush=True)
        print("************", flush=True)

        # Step 9.3 Put User in that Group
        add_user_to_group_request = requests.put(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/groups/{group_id}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        add_user_to_group_request.raise_for_status()
        print("User added to group successfully.", flush=True)

        query = "UPDATE user_registered SET group_assign_user_to_group = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 9.4: Map the role to the group
        map_role_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/groups/{group_id}/role-mappings/clients/{client_id}",
            json=get_role_new_client_request.json(),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        map_role_request.raise_for_status()

        query = "UPDATE user_registered SET group_frost_client_role_mapping = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 10 : GET CLIENT Secret of the new client

        get_client_secret_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/client-secret",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        get_client_secret_request.raise_for_status()
        client_secret = get_client_secret_request.json()["value"]

        # Step 11 : Generate new YML Template
        new_yml_template = generateYML(
            new_clientId, clientPORT, internalPORT, client_secret, KEYCLOAK_REALM, ROOT_URL,KEYCLOAK_SERVER_URL ,frost_newURL)
        
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
            ["docker-compose", "-p", new_clientId, "-f", f"yml_files/{new_clientId}.yml", "up", "-d"])

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

        node_red_port_check = check_column_data_exists(
            "node_red_port", cursor=cursor, db=db)

        if (node_red_port_check):
            new_node_red_port = get_max_column_value(
                "node_red_port", cursor, db) + 1
            collision_exist = check_variable_exists_in_ports(
                new_node_red_port, cursor, db)
            while (collision_exist):
                new_node_red_port += 1
                collision_exist = check_variable_exists_in_ports(
                    new_node_red_port, cursor, db)
            update_service_column(
                service_id, "node_red_port", new_node_red_port, cursor, db)
        else:
            new_node_red_port = PORT_DEFAULT_NODE_RED
            update_service_column(
                service_id, "node_red_port", new_node_red_port, cursor, db)

        # new_node_red_port = PORT_DEFAULT_NODE_RED+new_clientIDNumber
        new_node_red_port = new_node_red_port
        node_red_name = f"node_red_{service_id}"
        node_red_name_storage_name = f"node_red_storage_{service_id}"

        command_create_node_red_instance = f"docker run -d --restart always --init  -p {new_node_red_port}:1880 -v {node_red_name_storage_name}:/data --name {node_red_name} nodered/node-red"
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

        command_node_red_dependency_installation = ["docker", "exec", container_node_red_id, "bash", "-c",
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

        new_clientIDNumber_node_red = service_id
        new_clientId_node_red = f"node_red_{new_clientIDNumber_node_red}"

        # Step 15.2 : Create the new client in the new node-red
        nodered_newURL =  f"https://{new_node_red_port}-{NODERED_URL[len('https://'):]}"
        print(f"{nodered_newURL} DOMAIN PRINT", flush=True)

        create_client_request_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients",
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
                "redirectUris": [f"{nodered_newURL}/*"],
                "adminUrl": f"{nodered_newURL}",
                "rootUrl": f"{nodered_newURL}",
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
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients?clientId={new_clientId_node_red}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        get_client_request_node_red.raise_for_status()
        client_id_node_red = get_client_request_node_red.json()[0]["id"]

        # Step 15.5 : Create role admin, read, create, delete in the new node-red client

        create_role_admin_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
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
            f"{KEYCLOAK_SERVER_URL}//admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
            json={
                "name": "read"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_role_read_node_red.raise_for_status()

        create_role_update_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
            json={
                "name": "update"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_role_update_node_red.raise_for_status()
        create_role_create_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
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
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
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
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/roles",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        get_role_new_client_node_red.raise_for_status()

        # Step 15.7 : Do the role mapping for the new user

        role_mapping_request_node_red = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_id_node_red}",
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

        # Step 15.8 Role Mapping of the Node Red Client in the Group Generated
        map_role_request = requests.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/groups/{group_id}/role-mappings/clients/{client_id_node_red}",
            json=get_role_new_client_node_red.json(),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        map_role_request.raise_for_status()

        query = "UPDATE user_registered SET group_node_red_client_role_mapping = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 15.8 : Create the secret

        get_client_node_red_secret_request = requests.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_node_red}/client-secret",
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

        callbackURL = f"{nodered_newURL}/auth/strategy/callback"

        print(new_clientId_node_red + " TEST ", flush=True)

        replace_settings_file(node_red_name_storage_name,
                              new_clientId_node_red, node_red_client_secret, callbackURL, KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, email, ROOT_URL,nodered_newURL)

        # Successful settings.js update
        query = "UPDATE user_registered SET node_red_replace_settings = 1 WHERE token = %s;"
        print(query, flush=True)
        cursor.execute(query, (token,))
        db.commit()

        # Step 15.9 : Restart the node-red container

        restart_node_red_container = subprocess.run(
            f"docker restart {container_node_red_id}", shell=True, check=True)

        print(restart_node_red_container, flush=True) 
        
        # Step 16.0 Create nginx configuration for the above nodered application
        print("nodered port check again for func execution ,{new_node_red_port}")
    
        

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

        # Closing the connection
        cursor.close()
        db.close()

        # Send confirmation mail
        generate_success_email(firstName, email)
        thread = Thread(target=run_tasks_sequentially, args=(frost_newURL, nodered_newURL, clientPORT, new_node_red_port))
        # create_dns_and_generate_ssl(frost_newURL,"tumhefservicetest@gmail.com")
        # create_dns_and_generate_ssl(nodered_newURL,"tumhefservicetest@gmail.com")
        # append_https_server_block(frost_newURL,clientPORT)
        # append_https_server_block(nodered_newURL,new_node_red_port)
        thread.start()

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


@ app.route("/register", methods=["POST"])
def register():
    try:
        # print("before",request.json.get())
        KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
        KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
        KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
        KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
        KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")

        host = os.getenv("DATABASE_HOST")
        port = int(os.getenv("DATABASE_PORT"))
        user = os.getenv("DATABASE_USERNAME")
        password = os.getenv("DATABASE_PASSWORD")
        database = os.getenv("DATABASE_NAME")

        SMTP_SERVER = os.getenv("SMTP_SERVER")
        SMTP_PORT = int(os.getenv("SMTP_PORT"))
        SMTP_USERNAME = os.getenv("SMTP_USERNAME")
        SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
        print("check", KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD, KEYCLOAK_REALM, host, user, password, port, database,
                    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD)
        
        if not all([KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD, KEYCLOAK_REALM, host, user, password, port, database,
                    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD]):
            return jsonify(success=False, error="One or more .env variable is missing"), 500

        # Try to connect to the database
        db = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )

        # Check if the connection to the database was successful
        if db is None:
            return jsonify(success=False, error="Failed to connect to the database"), 500

        cursor = db.cursor()
        print("cursor",cursor)

        firstName = request.json.get("firstName")
        lastName = request.json.get("lastName")
        email = request.json.get("email")
        # password = request.json.get("password")

        # if not all([firstName, lastName, email]):
        #     return jsonify(success=False, error="Inputs are missing"), 400
        # commandTUM = ['ldapsearch', '-H', 'ldaps://iauth.tum.de/', '-D', 'cn=TUZEHEZ-KCMAILCHECK,ou=bindDNs,ou=iauth,dc=tum,dc=de', '-b',
        #               'ou=users,ou=data,ou=prod,ou=iauth,dc=tum,dc=de', '-x', '-w', 'HEF@sensorservice2023', f'(&(imAffiliation=member)(imEmailAdressen={email}))']

        # tumVerificationResult = verifyTUMresponseString(
        #     resultcommandTUM.stdout)

        # resultcommandTUM = subprocess.run(
        #     commandTUM, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # print(resultcommandTUM.stdout)
        # print(resultcommandTUM.stderr)

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
            return jsonify(success=True, message="Email will be sent again because you are already registered", code="A00001"), 400

        query = "SELECT * FROM user_registered WHERE email = %s AND isVerified = 1 AND isCompleted = 0"
        cursor.execute(query, (email,))
        result = cursor.fetchall()
        print("result",result)
        if len(result) > 0:
            generate_email(status=2, token=token,
                           firstName=firstName, expiredAt=expiredAt)
            return jsonify(success=False, message="Email will be sent again because you are not completed", code="A00002"), 400

        query = "SELECT * FROM user_registered WHERE email = %s AND isVerified = 1 AND isCompleted = 1"
        cursor.execute(query, (email,))
        result = cursor.fetchall()
        if len(result) > 0:
            return jsonify(success=False, error="You are already verified and registered in our system", code="A00003"), 400

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
        return jsonify(success=False, error="Failed to connect to the database", code="A00004"), 500

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

def process_dataitem_string(input_string):
    main_string, _ = input_string.split('(')

    if main_string == 'Things':
        return 'Devices'
    elif main_string == 'Sensors':
        return 'Sensors'
    elif main_string == 'ObservedProperties':
        return 'Measurement Property'
    elif main_string == 'Datastreams':
        return 'Datastreams'
    else:
        return None
            
    return None

def extract_number(input_string):
    # Use regular expression to extract the number from the input string
    match = re.match(r'.*\((\d+)\)', input_string)
    if match:
        return int(match.group(1))
    else:
        return None

# detete

@app.route("/delete", methods=["POST"])
def delete():
    ROOT_URL = os.getenv("ROOT_URL")

    # check if request is json
    if not request.is_json:
        return jsonify(success=False, error="Request is not JSON"), 400

    # get token from header and check if it exists

    data = request.json
    token = request.headers.get("Authorization")
    url = data.get("url")
    FROST_PORT = data.get("FROST_PORT")
    keycloak_id=data.get("keycloak_id")

    print(token, flush=True)
    print(url, flush=True)
    print(FROST_PORT, flush=True)

    if not all([token, url, FROST_PORT, ROOT_URL,keycloak_id]):
        return jsonify(success=False, error="Inputs are missing"), 400

    URL_TO_EXECUTE = f"{ROOT_URL}:{FROST_PORT}/FROST-Server/v1.0/{url}"
    
    attribute_type=process_dataitem_string(url)
    attribute_id=extract_number(url)
    method="DELETE"

    print(URL_TO_EXECUTE, flush=True)
    
    DATABASE_HOST = os.getenv("DATABASE_HOST")
    DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
    DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
    DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
    DATABASE_NAME = os.getenv("DATABASE_NAME")

    # Try to connect to the database
    db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                            user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)

    # Check if the connection to the database was successful
    if db is None:
        return jsonify(success=False, error="Failed to connect to the database"), 500

    cursor = db.cursor()

    try:
        # Step 1: Get access token
        delete_request = requests.delete(
            f"{URL_TO_EXECUTE}",
            # Authorization token as a header
            headers={"Authorization": f"Bearer {token}"}
        )

        # Check if response has content
        if delete_request.content:
            response = delete_request.json()
            print(response, flush=True)
        else:
            response = None
        
        query = "INSERT INTO logs (keycloak_id, method, attribute_type, attribute_id, frost_port) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(
            query, (keycloak_id, method, attribute_type,attribute_id,FROST_PORT))
        db.commit()

        # get status code
        status_code = delete_request.status_code
        if status_code == 200:
            return jsonify(success=True), 200
        else:
            return jsonify(success=False, error=response), 500

    except json.JSONDecodeError as e:
        print(e, flush=True)
        return jsonify(success=False, error="Error parsing response as JSON"), 500
    except requests.exceptions.RequestException as e:
        print(e, flush=True)
        return jsonify(success=False, error="Error making the delete request"), 500
    except Exception as e:
        print(e, flush=True)
        return jsonify(success=False, error="Server Error"), 500


@app.route("/update", methods=["PATCH"])
def update():
    ROOT_URL = os.getenv("ROOT_URL")

    data = request.json
    token = request.headers.get("Authorization")
    url = data.get("url")
    FROST_PORT = data.get("FROST_PORT")
    body = data.get("body")
    keycloak_id=data.get("keycloak_id")

    # print(token, flush=True)
    print(url, flush=True)
    # print(FROST_PORT, flush=True)

    # Access the entire JSON object
    # print("JSON Object:", body)

    if not all([token, url, FROST_PORT, ROOT_URL, body,keycloak_id]):
        return jsonify(success=False, error="Inputs are missing"), 400

    URL_TO_EXECUTE = f"{ROOT_URL}:{FROST_PORT}/FROST-Server/v1.0/{url}"

    print(URL_TO_EXECUTE, flush=True)
    print(url, flush=True)
    
    attribute_type=process_dataitem_string(url)
    attribute_id=extract_number(url)
    method="UPDATE"
    
    print(attribute_type,flush=True)
    print(attribute_id,flush=True)
    print(keycloak_id,flush=True)

    DATABASE_HOST = os.getenv("DATABASE_HOST")
    DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
    DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
    DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
    DATABASE_NAME = os.getenv("DATABASE_NAME")

    # Try to connect to the database
    db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                            user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)

    # Check if the connection to the database was successful
    if db is None:
        return jsonify(success=False, error="Failed to connect to the database"), 500

    cursor = db.cursor()

    try:
        update_request = requests.patch(
            URL_TO_EXECUTE,
            headers={"Authorization": f"{token}",
                     "Content-Type": "application/json"},
            json=body
        )
        # print(update_request.content.decode('utf-8'), flush=True)

        # Check if response has content
        if update_request.content:
            response = update_request.json()
            print(response, flush=True)
        else:
            response = None

        # STORE LOGS 
        query = "INSERT INTO logs (keycloak_id, method, attribute_type, attribute_id, frost_port) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(
            query, (keycloak_id, method, attribute_type,attribute_id,FROST_PORT))
        db.commit()

        # get status code
        status_code = update_request.status_code
        if status_code == 200:
            return jsonify(success=True), 200
        else:
            return jsonify(success=False, error=response), 500

    except json.JSONDecodeError as e:
        print(e, flush=True)
        return jsonify(success=False, error="Error parsing response as JSON"), 500
    except requests.exceptions.RequestException as e:
        print(e, flush=True)
        return jsonify(success=False, error="Error making the delete request"), 500
    except Exception as e:
        print(e, flush=True)
        return jsonify(success=False, error="Server Error"), 500


def generate_contact_email(first_name, last_name, email, subject, details, type):
    try:

        SMTP_SERVER = os.getenv("SMTP_SERVER")
        SMTP_PORT = int(os.getenv("SMTP_PORT"))
        SMTP_USERNAME = os.getenv("SMTP_USERNAME")
        SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = "sensorHUB Contact - " + type + " - " + subject
        msg['From'] = SMTP_USERNAME
        msg['To'] = "tumhefservicetest@gmail.com"

        html = """\
         <html>
            <head></head>
            <body style="text-align: center;">
                <h2>Hi,</h2>
                <p>A new contact request has been submitted:</p>
              <p><b>Firstname: </b>{firstname}</p>
                 <p><b>Surname: </b>{lastName}</p>
              <p><b>Email: </b>{email}</p>
                 <p><b>Type: </b>{type}</p>
                 <p><b>subject: </b>{subject}</p>
                 <p><b>Details: </b>{details}</p>
              
            </body>
            </html>
        """
        # Replace placeholders with actual values
        html = html.format(firstname=first_name, lastName=last_name,
                           email=email, type=type, subject=subject, details=details)

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
    

def generate_mutation_error_log_email(keycloak_id, method, attribute,attribute_id,frost_port):
    try:

        SMTP_SERVER = os.getenv("SMTP_SERVER")
        SMTP_PORT = int(os.getenv("SMTP_PORT"))
        SMTP_USERNAME = os.getenv("SMTP_USERNAME")
        SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = "sensorHUB Mutation Error Log"
        msg['From'] = SMTP_USERNAME
        msg['To'] = "tumhefservicetest@gmail.com"

        html = f"""\
            <html>
            <head></head>
            <body style="text-align: center;">
                <h2>Hi,</h2>
                <p>A new bug was encountered:</p>
                <p><b>User: </b>{keycloak_id}</p>
                <p><b>Method: </b>{method}</p>
                <p><b>Attribute: </b>{attribute}</p>
        """

        if attribute_id is not None:
            html += f"<p><b>Attribute_ID: </b>{attribute_id}</p>"

        html += """
            <p><b>Frost Port: </b>{frost_port}</p>
            </body>
            </html>
        """
        # Replace placeholders with actual values
        html = html.format(keycloak_id=keycloak_id, method=method,
                           attribute=attribute,attribute_id=attribute_id,frost_port=frost_port)

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


@app.route("/send_email/contact", methods=["POST"])
def send_email():
    try:
        data = request.json
        type = data.get("type")
        subject = data.get("subject")
        details = data.get("details")
        email = data.get("email")
        first_name = data.get("first_name")
        last_name = data.get("last_name")

        print(type, subject, details, email, first_name, last_name, flush=True)

        if not all([type, subject, details, email, first_name, last_name]):
            return jsonify(success=False, error="Inputs are missing"), 400

        generate_contact_email(first_name, last_name,
                               email, subject, details, type)

        DATABASE_HOST = os.getenv("DATABASE_HOST")
        DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
        DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
        DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
        DATABASE_NAME = os.getenv("DATABASE_NAME")

        # Try to connect to the database
        db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                             user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)

        # Check if the connection to the database was successful
        if db is None:
            return jsonify(success=False, error="Failed to connect to the database"), 500

        cursor = db.cursor()
        query = "INSERT INTO contact_form (type, subject, details, email, first_name, last_name) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(
            query, (type, subject, details, email, first_name, last_name))
        db.commit()

        return jsonify(success=True), 200
    except Exception as e:
        print(e, flush=True)
        return jsonify(success=False, error="Server Error"), 500


@app.route("/mutation_error_logs", methods=["POST"])
def mutation_error_logs():
    try:
        data = request.json
        keycloak_id = data.get("keycloak_id")
        method = data.get("method")
        attribute = data.get("attribute")
        attribute_id = data.get("attribute_id")
        frost_port = data.get("frost_port")
  
        print(keycloak_id, method, attribute,attribute_id,frost_port, flush=True)

        if not all([keycloak_id, method, attribute]):
            return jsonify(success=False, error="Inputs are missing"), 400

        generate_mutation_error_log_email(keycloak_id, method, attribute,attribute_id,frost_port)

        DATABASE_HOST = os.getenv("DATABASE_HOST")
        DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
        DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
        DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
        DATABASE_NAME = os.getenv("DATABASE_NAME")

        # Try to connect to the database
        db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                             user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)

        # Check if the connection to the database was successful
        if db is None:
            return jsonify(success=False, error="Failed to connect to the database"), 500

        cursor = db.cursor()
        query = "INSERT INTO mutation_error_logs (keycloak_id, method, attribute, attribute_id, frost_port) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(
            query, (keycloak_id, method, attribute,attribute_id,frost_port))
        db.commit()

        return jsonify(success=True), 200
    except Exception as e:
        print(e, flush=True)
        return jsonify(success=False, error="Server Error"), 500

@app.route("/reset_password", methods=["POST"])
def reset_password():
        try:
            data = request.json
            user_id = data.get("user_id")
            password = data.get("password")
            
            if not all([user_id, password]):
                return jsonify(success=False, error="Inputs are missing"), 400
            
            KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
            KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
            KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
            KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
            KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
            
            # Step 1: Get access token
            token_request = requests.post(
                f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
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
            
            # reset password request using
            change_password_request = requests.put(
                f"{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/reset-password",
                json={
                    "type": "password",
                    "value": password
                },
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
            )
            
            if change_password_request.status_code != 204:
                return jsonify(success=False, error="Error when changing password"), 500
            
            return jsonify(success=True), 200
        except Exception as e:
            print(e, flush=True)
            return jsonify(success=False, error="Server Error"), 500


@app.route("/logs", methods=["GET"])
def logs():
    try:
        DATABASE_HOST = os.getenv("DATABASE_HOST")
        DATABASE_USERNAME = os.getenv("DATABASE_USERNAME")
        DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
        DATABASE_PORT = int(os.getenv("DATABASE_PORT"))
        DATABASE_NAME = os.getenv("DATABASE_NAME")
        
        keycloak_id = request.args.get("keycloak_id")

        print(keycloak_id, flush=True)
        
        if not all([keycloak_id]):
            return jsonify(success=False, error="Inputs are missing"), 400
         
        db = pymysql.connect(host=DATABASE_HOST, port=DATABASE_PORT,
                             user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)
         
        if db is None:
            return jsonify(success=False, error="Failed to connect to the database"), 500

        cursor = db.cursor()
        
        # Get all the logs from the database
        query = "SELECT * FROM logs WHERE keycloak_id = %s ORDER BY created_at DESC;"
        
        # return as json object
        cursor.execute(query, (keycloak_id,))
        result = cursor.fetchall()
        
        json_logs = []
        for log in result:
            json_logs.append({
                "id": log[0],
                "keycloak_id": log[1],
                "method": log[2],
                "attribute": log[4],
                "attribute_id": log[3],
                "frost_port": log[5],
                "created_at": log[6]
            })
            
            
        print(json_logs, flush=True)

        # Closing the connection
        cursor.close()
        db.close()

        return jsonify(success=True, logs=json_logs), 200
    except Exception as e:
        print(e, flush=True)
        return jsonify(success=False, error="Server Error"), 500


@app.route("/test_db_connection", methods=["GET"])
def test_db_connection():
    try:
        # Get database credentials from environment variables
        host = os.getenv("DATABASE_HOST")
        port = int(os.getenv("DATABASE_PORT"))
        user = os.getenv("DATABASE_USERNAME")
        password = os.getenv("DATABASE_PASSWORD")
        database = os.getenv("DATABASE_NAME")

        # Establish connection to MySQL server
        connection = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )

        # Close the connection
        connection.close()

        # If no exception is raised, return success response
        return jsonify(success=True, message="Database connection successful")

    except Exception as e:
        # If an exception is raised, return error response
        return jsonify(success=False, error=str(e))
@app.route('/pathcheck', methods=['GET'])
def test_path():
    try:
        # Replace "node_red_storage_38" with the dynamic volume name
        node_red_storage = "node_red_storage_38"
        create_dns_and_generate_ssl('https://6033-frost-dev.hef.tum.de','tumhefservicetest@gmail.com')
        # append_https_server_block('https://6023-frost-dev.hef.tum.de',6023)
        
        # Construct the directory path
        directory = f"/var/lib/docker/volumes/{node_red_storage}/_data"
        
        # Check if the directory exists
        if os.path.exists(directory):
            current_path = os.getcwd()
            return jsonify({'success': True, 'message': f'Directory {directory} exists', 'current_path': current_path})
        else:
            return jsonify({'success': False, 'error': f'Directory {directory} does not exist'})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Error: {e}"})

 

    
if __name__ == '__main__':
    app.run(host="0.0.0.0", port="4500")

    
