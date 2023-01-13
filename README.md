# KEYCLOAK_SERVICES

This repository is used to create endpoint API for our Web Application.
Requests:

1) POST ( **/register)**

This endpoint checks first if all the parameters such have been received:
```markdown
- firstName
- lastname
- email
- username
- password
```

The first HTTP request we do by retrieving the Token using the credentials by the user that has access to store a new user. 

Code: 
```
token_request = requests.post(
            "http://localhost:8080/realms/{realm}/protocol/openid-connect/token",
            data={
                "client_id": {CLIENT_ID},
                "username": {Admin_username},
                "password": {Admin_password},
                "grant_type": "password",
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
```

After than we use the token received to create the second request which creates the new user in the Keycloak database.

```
"http://localhost:8080/admin/{realm}/keycloak-react-auth/users",
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
```

If everything works perfectly fine and receive a 200 status code, we return  a json with `success:True`.
If we receive a status code of 409, means that with the credentials given, a user exists.
