
# KEYCLOAK_SERVICES

The script is designed to interact with a local Keycloak server to perform various actions (Currently creating new user, client, roles, and role-mapping)

1) **POST** - */register*


When a user makes a POST request to the endpoint "/register" with a JSON payload containing their first name, last name, email, username, and password, the following process occurs:

 - The script makes a POST request to the endpoint
   "http://localhost:8080/realms/keycloak-react-auth/protocol/openid-connect/token"
   with data in the form of "client_id", "username", "password",
   "grant_type" and headers in the form of "Content-Type" in order to
   get an access token from the Keycloak server.
   
 
 - Using the obtained access token, the script makes a POST request to  
   the endpoint   
   "http://localhost:8080/admin/realms/keycloak-react-auth/users" with  
   the JSON payload containing the user's first name, last name, email, 
   credentials (password), username, enabled status to create a new   
   user.

   

 - The script then sends an email to the newly registered user, but the 
   functionality is commented out.

   
  

 - Using the access token, the script makes a GET request to the   
   endpoint   
   "http://localhost:8080/admin/realms/keycloak-react-auth/clients" in  
   order to get a list of all clients.
 - The script then uses the function "get_max_frost()" to generate a new
   client ID by incrementing the highest "frost_" client ID by 1.

   

 - Finally, the script makes a POST request to the endpoint   
   "http://localhost:8080/admin/realms/keycloak-react-auth/clients" with
   the JSON payload containing the newly generated client ID and enabled
   status to create a new client on the Keycloak server.

   
   

 - The script makes a POST request to the endpoint   
   "http://localhost:8080/admin/realms/keycloak-react-auth/roles" to   
   create a new role for the user.

   
   

 - Using the access token, the script makes a POST request to the   
   endpoint   
   "http://localhost:8080/admin/realms/keycloak-react-auth/users/user_id/role-mappings/realm"
   to map the new role to the newly created user.

   
   In addition, the script uses the Flask-CORS extension to handle CORS
   requests, allowing the app to receive cross-origin requests, this is
   done by instantiating the CORS class and passing the app instance to
   it at the beginning of the script.
   
	  This script is designed to run on localhost and assumes that
   the Keycloak server is also running on localhost.
