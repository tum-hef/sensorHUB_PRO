




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
   
   
## TUM-LDAP-request
   
### Overview
The TUM directory service (LDAP) makes basic master and authentication data, such as name, e-mail or TUM identifier, available to authorized organizational units via an LDAP interface. This service was established as part of the IntegraTUM project under the name "MetaDirectory". With its help, the effort of the own user administration can be minimized.

The authentication service can be used to authenticate persons who are registered in the directory service. The current group of persons includes all persons active in TUMonline with TUM identification, i.e. employees, students, guests and alumni of TUM. Applicants are available from the time of acceptance.

Please note that authentication via LDAP is not a recommended method, especially for web applications. We strongly recommend the use of SAML2 via Shibboleth Login (or OAuth2 Login) and require a compelling written justification otherwise. New use cases must be limited to using the LDAP Directory as a directory service.

### Implement and use LDAP
- Ask for username and password with HEF-admin
	
- Install ldap-utils on linux: ```apt install ldap-utils```
- Change password: 
    - https://wiki.tum.de/pages/viewpage.action?pageId=20881370
    - ```ldappasswd -A -S -W -H "ldaps://iauth.tum.de:636" -D "cn=TUZEHEZ-KCMAILCHECK,ou=bindDNs,ou=iauth,dc=tum,dc=de"```
    - You will then be asked to enter the old password twice, then the new password twice, and then again to enter and confirm the old password once.

- Request/verify mail-adresse or others with ldapsearch:
```ldapsearch -H "ldaps://iauth.tum.de/" -D "cn=LDAP-USERNAME-HERE,ou=bindDNs,ou=iauth,dc=tum,dc=de" -b "ou=users,ou=data,ou=prod,ou=iauth,dc=tum,dc=de" -W "(&(imAffiliation=member)(imEmailAdressen=david.gackstetter@tum.de))"```

    - imAffiliation may be either student or member
- Automate the ldapsearch by providing password with the request by adding -x and -w (instead of -W) flags together with the password:

```ldapsearch -H "ldaps://iauth.tum.de/" -D "cn=TUZEHEZ-KCMAILCHECK,ou=bindDNs,ou=iauth,dc=tum,dc=de" -b "ou=users,ou=data,ou=prod,ou=iauth,dc=tum,dc=de" -x -w <enter_password_here_without_quotation_marks> "(&(imAffiliation=member)(imEmailAdressen=david.gackstetter@tum.de))"```
    
    
   
## Configuration

Preconfig:

1) ** Download Docker** 

------------------------------------------------------------------------------------
1) **Install keycloak** 
``` docker run -d --name keycloak --restart=always -p 8080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin -e PROXY_ADDRESS_FORWARDING=true jboss/keycloak  ```

2) **Remove HTTPS (Not recommanded)**

```docker exec -it {contaierID} bash```

  
```   cd /opt/jboss/keycloak/bin```
        
``` ./kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user  admin``` 
 
 ``` ./kcadm.sh update realms/master -s sslRequired=NONE```

3) **Create new realm (Or use Master)**

4) **Create new client**
In the root URL use the  frontend url
```e.g. http://localhost:3000/```

5) **Create new user (Or use admin)**

6) **Create a static password and remove Temporary password**

7) **In role Mapping of the user give access**

8) **Install mysql**
```docker run -d -p 3306:3306 --name mysql -e MYSQL_ROOT_PASSWORD= YOUR_PASSWORD> mysql ```

9) Clone Git repository 

``` git clone https://github.com/HEFLoRa/KEYCLOAK_SERVICES ```

10) **Execute in the database "initial_queries.sql" file**

11) **Fill variables in .env**

```
ROOT_URL=

KEYCLOAK_SERVER_URL=
KEYCLOAK_CLIENT_ID=
KEYCLOAK_USERNAME=
KEYCLOAK_PASSWORD=
KEYCLOAK_REALM=

SMTP_SERVER=
SMTP_PORT=
SMTP_USERNAME=
SMTP_PASSWORD=

DATABASE_HOST=
DATABASE_USERNAME=
DATABASE_PASSWORD=
DATABASE_PORT=
DATABASE_NAME=

# FLUSK Service
SERVER_URL=
```

Example .env for production (HTTPs included)

```
ROOT_URL=https://keycloak.hef.tum.de

  

KEYCLOAK_SERVER_URL=https://keycloak.hef.tum.de

KEYCLOAK_CLIENT_ID=hefSensorHub_production

KEYCLOAK_USERNAME=admin

KEYCLOAK_PASSWORD=admin

KEYCLOAK_REALM=master

  

SMTP_SERVER=smtp.gmail.com

SMTP_PORT=587

SMTP_USERNAME=tumhefservicetest@gmail.com

SMTP_PASSWORD=PW

  

DATABASE_HOST=HOST

DATABASE_USERNAME=USER

DATABASE_PASSWORD=PW

DATABASE_PORT=3306

DATABASE_NAME=tumservices

  

# FLUSK Service

SERVER_URL=https://services.hef.tum.de

```


11) Allow Access to all ports

```
    sudo ufw allow in from any to any
    sudo ufw allow out from any to any
```

12) Create image from the docker file inside repository

``docker build -t hefsensorhub_image_backend .``

13) Run Application
`docker run -d -p 4500:4500 --env-file .env --name HEFsensorHUB_container_backend -v /var/run/docker.sock:/var/run/docker.sock --restart always hefsensorhub_image_backend`

    

## Workflow of Ports stored 

![code2flow_Vm3Zwb (2)](https://user-images.githubusercontent.com/49834648/231116263-4a45142e-24aa-4a15-b704-104c3c751a12.png)


## Groups

When Generating a group, it will have two key value pairs.

 1. Group Name (The Email of the first user)
 2.  Group Type  (Individual/Instituion/Project)
