
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
   
   
   2.) LDAP-request
   
- Overview
The TUM directory service (LDAP) makes basic master and authentication data, such as name, e-mail or TUM identifier, available to authorized organizational units via an LDAP interface. This service was established as part of the IntegraTUM project under the name "MetaDirectory". With its help, the effort of the own user administration can be minimized.

The authentication service can be used to authenticate persons who are registered in the directory service. The current group of persons includes all persons active in TUMonline with TUM identification, i.e. employees, students, guests and alumni of TUM. Applicants are available from the time of acceptance.

Please note that authentication via LDAP is not a recommended method, especially for web applications. We strongly recommend the use of SAML2 via Shibboleth Login (or OAuth2 Login) and require a compelling written justification otherwise. New use cases must be limited to using the LDAP Directory as a directory service.

- Ask for username and password with HEF-admin
	
- Install ldap-utils on linux: ```apt install ldap-utils```
- Change password: 
    - https://wiki.tum.de/pages/viewpage.action?pageId=20881370
    - ```ldappasswd -A -S -W -H "ldaps://iauth.tum.de:636" -D "cn=TUZEHEZ-KCMAILCHECK,ou=bindDNs,ou=iauth,dc=tum,dc=de"```
    - You will then be asked to enter the old password twice, then the new password twice, and then again to enter and confirm the old password once.

- Request/verify mail-adresse or others with ldapsearch:
```ldapsearch -H "ldaps://iauth.tum.de/" -D "cn=TUZEHEZ-KCMAILCHECK,ou=bindDNs,ou=iauth,dc=tum,dc=de" -b "ou=users,ou=data,ou=prod,ou=iauth,dc=tum,dc=de" -W (&(imAffiliation=member)(imEmailAdressen=david.gackstetter@tum.de))"```
   
