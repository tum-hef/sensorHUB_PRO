from flask import Flask, request, jsonify
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

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
        token_request = requests.post(
            "http://localhost:8080/realms/keycloak-react-auth/protocol/openid-connect/token",
            data={
                "client_id": "react",
                "username": "parid",
                "password": "1",
                "grant_type": "password",
                "credentials": [
                    {
                        "type": "password",
                        "value": password,
                        "temporary": False
                    }
                ]
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )

        token_request.raise_for_status()
        access_token = token_request.json()["access_token"]

        create_user_request = requests.post(
            "http://localhost:8080/admin/realms/keycloak-react-auth/users",
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
                "username": username,
                "enabled": True
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        create_user_request.raise_for_status()
        return jsonify(success=True, message="User created successfully")
    except requests.exceptions.HTTPError as err:
        if err.response.status_code == 409:
            return jsonify(success=False, error="Users Exists"), 409
        else:
            return jsonify(success=False, error="Server Error"), 500
    except Exception as err:
        return jsonify(success=False, error=str(err)), 500

if __name__ == '__main__':
    app.run(port=4500)
