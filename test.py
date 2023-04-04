from flask import Flask, request, jsonify,render_template
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
    node_red_nums = [x for x in arr if x.startswith("node_red_") and x[10:].isdigit()]
    if not node_red_nums:
        return 0
    max_num = max(node_red_nums, key=lambda x: int(x.split("_")[1]))
    return int(max_num.split("_")[1]) + 1



def generateYML(clientID, port, secondPort, clientSecret,KEYCLOAK_REALM,ROOT_URL):
    yml_template = """
    version: '3'
    services:
      web:
        image: fraunhoferiosb/frost-server:2.0
        container_name: {clientID}
        environment:
          - serviceRootUrl=http://{ROOT_URL}:{port}/FROST-Server
          - http_cors_enable=true
          - http_cors_allowed.origins=*
          - persistence_db_driver=org.postgresql.Driver
          - persistence_db_url=jdbc:postgresql://database:5432/sensorthings
          - persistence_db_username=sensorthings
          - persistence_db_password=ChangeMe
          - persistence_autoUpdateDatabase=true
          - persistence_alwaysOrderbyId=true
          - auth.provider=de.fraunhofer.iosb.ilt.frostserver.auth.keycloak.KeycloakAuthProvider
          - auth.keycloakConfigUrl=http://{ROOT_URL}:8080/auth/realms/{KEYCLOAK_REALM}/clients-registrations/install/{clientID}
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
    return yml_template.format(clientID=clientID, secondPort=secondPort,  port=port, clientSecret=clientSecret,KEYCLOAK_REALM=KEYCLOAK_REALM,ROOT_URL=ROOT_URL)

@app.route('/test', methods=['POST']) 
def my_page():
    try:
        KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
        KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
        KEYCLOAK_USERNAME = os.getenv("KEYCLOAK_USERNAME")
        KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")
        KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
        KEYCLOAK_DOMAIN = os.getenv("KEYCLOAK_DOMAIN")

        ROOT_URL=os.getenv("ROOT_URL")

        req_data = request.get_json()
        firstName = req_data['firstName']
        lastName = req_data['lastName']
        email = req_data['email']
        password=req_data['password']

        # return jsonify(req_data)

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
        create_client_request = requests.post(
             f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
            json={
                "clientId": new_clientId,
                "enabled": True,
                "publicClient": False,  # Access type: confidential
                # This is the URL of the Keycloak
                "redirectUris": [f"{KEYCLOAK_SERVER_URL}/*"],
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

                create_client_request = requests.post(
                      f"{KEYCLOAK_SERVER_URL}/auth/admin/realms/{KEYCLOAK_REALM}/clients",
                    json={
                        "clientId": new_clientId,
                        "enabled": True,
                        # This is the URL of the Keycloak
                        "redirectUris": [f"{KEYCLOAK_SERVER_URL}/*"],
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

        PORT = 6000
        SECONDPORT = 1890

        clientPORT = PORT+new_clientIDNumber
        internalPORT = SECONDPORT+new_clientIDNumber

        new_yml_template = generateYML(
            new_clientId, clientPORT, internalPORT, client_secret,KEYCLOAK_REALM,ROOT_URL)

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
        ["sudo","docker-compose","-p", new_clientId, "-f", f"yml_files/{new_clientId}.yml", "up", "-d"])

        print(subprocess_run_frost, flush=True)

        # Check if any error occurs when running the new yml file
        if subprocess_run_frost.returncode != 0:
            return render_template('token.html', error="Error when running the new yml file")

        
        return jsonify(success=True, msg="Success"),200
    
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
        line_number = tb[-2].split(", ")[1].strip()  # Get the line number from the second-to-last line of the traceback
        print("***********************************************",flush=True)
        print(error_message,flush=True)
        print("***********************************************",flush=True)
        print(line_number,flush=True)
        
        # tb = err.__traceback__
        # # get the line number of the error
        # line_num = tb.tb_lineno
        # # print the error message and line number
        # print(f"Error on line {line_num}: {err}",flush=True)

        return jsonify(success=False, error=str(err)), 500
        # return render_template('token.html', error=str(err))
    
if __name__ == '__main__':
    app.run(host="0.0.0.0",port="4500")
