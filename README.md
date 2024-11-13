
# sensorHUB - PRO Version
The sensorHUB software is a novel, open-source software stack for enhanced accessibility and secure interoperability in IoT project management. It is developed by Technical University of Munich's (TUM) Hans Eisenmann-Forum for Agricultural Sciences (HEF). For more background details see https://github.com/tum-hef/sensorHUB/ and the related publication [sensorHUB – a Novel, Open-source Software Stack for Enhanced Accessibility and Secure Interoperability in IoT Project Management](10.5194/isprs-archives-xlviii-4-2024-197-2024).

This repository presents the sensorHUB's Lite version, which in contrast to the Pro version (provided in a separate repository: [sensorHUB_PRO](https://github.com/HEFLoRa/sensorHUB_PRO) is only based on HTTP-network communication without operationally oriented domain-specific adresses and SSL-enhancement. 


## Conceptual Overview
The sensorHUB technology stack comprises the following components:

1.  **Keycloak** for authentication and overall application security, serving as the top layer that protects NodeRED, Frontend, Backend, FROST-server, and MySQL.
    
2.  **Frontend** developed using React with Typescript, serving as the web application. Upon user authentication, it can connect to the Node-RED page.
    
3.  **Backend** implemented in Python using Flask, providing functionalities such as user registration, various procedures linked to FROST-server, email sending, and log tracking.
        
4.  **FROST-server** is utilized for specific procedures within the backend, contributing to the overall capabilities of the system.
    
5.  **MySQL** serves as the database, tracking user registrations, verifications, and error logs.

6.  **NodeRED**, integrated into the stack, enhances the overall functionality and connectivity of the application.


![iot_stack_concept_v11](https://github.com/user-attachments/assets/30ca3929-fc20-429e-bf59-9ab4172723df)


## Changes and Updates

See the [Change Log](CHANGELOG.md).

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create.
Any contributions are greatly appreciated.
You can read more in our [contribution guidelines](CONTRIBUTING.md).

## Compiling

### Setting up Certbot for Let's Encrypt
### Certbot is a free and open-source tool that simplifies obtaining SSL/TLS certificates from Let’s Encrypt.
    sudo apt update
    sudo apt install certbot
### Obtain Certificate for the sensorHUB PRO
    sudo certbot certonly --manual -d example.com 
-   `sudo`: Runs the command with superuser privileges, allowing Certbot to save the SSL certificate files to system directories.
-   `certbot`: The main tool for requesting and managing SSL certificates from Let’s Encrypt.
-   `--manual`: Specifies manual mode, which requires you to manually create DNS records to verify domain ownership. This is often used when automated DNS API integration is not available or when requesting a wildcard certificate.
-   `-d example.com`: Obtains a certificate for the main domain example.com.

### Obtain Certificate for the Keycloak
     sudo certbot certonly --manual -d keycloak.example.com
  

        

### Running Keycloak 
  #### Creating common network for focker 
     docker network create sensorhub_pro
      
  #### Installing Keycloak and running it from docker. Create a docker-compose.yaml file.
   ```
version: "2.3"

services:
  postgres:
    image: postgres:16.0
    container_name: postgres
    restart: always
    ports:
      - "5432:5432"
    volumes:
      - ./data:/var/lib/postgresql/data
    networks:
      - keycloak-network
    environment:
      POSTGRES_USER: keycloak_user
      POSTGRES_PASSWORD: keycloak_password
      POSTGRES_DB: keycloak_db

  keycloak:
    image: quay.io/keycloak/keycloak:23.0.6
    container_name: keycloak
    restart: always
    ports:
      - "8080:8080"
      - "8443:8443"
    depends_on:
      - postgres
    command:
      - start
    networks:
      - keycloak-network
    environment:
      KC_DB: postgres
      KC_DB_URL_HOST: postgres
      KC_DB_URL_DATABASE: keycloak_db
      KC_DB_USERNAME: keycloak_user
      KC_DB_PASSWORD: keycloak_password
      KC_HOSTNAME_URL: https://my-keycloak-domain.com
      KC_HOSTNAME_STRICT_HTTPS: "true"
      KC_HOSTNAME_STRICT_BACKCHANNEL: "true"
      KC_PROXY: edge
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin_password
      KEYCLOAK_FRONTEND_URL: https://my-keycloak-domain.com

  nginx:
    image: nginx:latest
    container_name: nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - /etc/letsencrypt:/etc/letsencrypt
    depends_on:
      - keycloak
    networks:
      - keycloak-network

networks:
  keycloak-network:
    driver: bridge

```     

     docker run -d --name keycloak --network=sensorhub_lite --restart=always -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -e PROXY_ADDRESS_FORWARDING=true quay.io/keycloak/keycloak:23.0.6 start-dev
-   `docker run`: This is the command to run a Docker container.
-   `-d`: This flag stands for "detached" mode, which means the container runs in the background.
-   `--name keycloak`: This flag assigns the name "keycloak" to the running container.
-   `--network`: This flag assigns the network to the running container.
-   `--restart always`: This flag ensures that the container automatically restarts if it stops unexpectedly.
-   `-p 8080:8080`: This flag maps port 8080 on the host machine to port 8080 on the container. Port 8080 is typically used for accessing Keycloak's web interface.
-   `-e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin`: These environment variables set the username and password for the initial Keycloak administrator account. In this case, the username is "admin" and the password is also "admin."
-   `-e PROXY_ADDRESS_FORWARDING=true`: This environment variable is set to "true" and is related to handling proxy address forwarding. It is often used when Keycloak is running behind a reverse proxy.
-   `quay.io/keycloak/keycloak:23.0.6`: This is the name of the Docker image and 23.0.6 is the version that will be used to create the container. It specifies the official Keycloak Docker image provided by the quay organization.
-   `start-dev`: This is used because we are using it in HTTP meanwhile start is used for HTTPS.


  
The provided Docker command runs a Keycloak container in detached mode, naming it "keycloak," ensuring automatic restarts, mapping host port 8080 to the container's port 8080, setting the initial admin credentials to admin/admin (**for security purpose, please change the default password**), and enabling proxy address forwarding. The container is based on the official Keycloak Docker image (`quay.io/keycloak/keycloak`).

#### Removing HTTPs (Optional and NOT recommended)

`contaierID` - container ID of the keycloak

    docker exec -it {contaierID} bash
    cd /opt/keycloak/bin
    ./kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin
    (Enter your password that you typed in the arguments of running keycloak on the first step)
    ./kcadm.sh update realms/master -s sslRequired=NONE

 1. Create new realm (Or use Master)
 2. Create a new client, in the `clientI ID`, put the name of the client the you are going to use e.g. `hefSensorHub_production`
 3. In the Root URL, please use the frontend URL (also port if you are using it/or you can use dev URL `e.g. http://localhost:3000`

### Running a MySQL instance and cloning Backend

#### Pulling MySQL image and creating an instance 

    docker run -d -p 3306:3306 --name mysql --restart always -e MYSQL_ROOT_PASSWORD=<YOUR_PASSWORD> mysql

-   `docker run`: This is the command to run a Docker container.
-   `-d`: This flag stands for "detached" mode, which means the container runs in the background.
-   `-p 3306:3306`: This flag maps port 3306 on the host machine to port 3306 on the container. Port 3306 is the default port for MySQL database connections.
-   `--name mysql`: This flag assigns the name "mysql" to the running container.
-   `--restart always`: This flag ensures that the container automatically restarts if it stops unexpectedly.
-   `-e MYSQL_ROOT_PASSWORD=<YOUR_PASSWORD>`: This environment variable sets the root password for the MySQL database. Replace `<YOUR_PASSWORD>` with the desired password. This is important for securing the MySQL instance.
-   `mysql`: This is the name of the Docker image that will be used to create the container. It specifies the official MySQL Docker image.

![image (5)](https://github.com/HEFLoRa/HEF-sensorHUB/assets/40120846/bb91afe1-96a5-40da-9837-6bfc71102309)


#### Cloning Backend from GitHub

  ```git clone https://github.com/HEFLoRa/sensorHUB_LITE ```

   ```
 cd sensorHUB_LITE
   ```
  
    
Run the Initial queries  `sensorHUB_LITE/initial_queries.sql` on the DB instance you created.

Inside the the sensorHUB_LITE folder, create a new file `.env` for env variables, you also follow `.env example`

```
ROOT_URL= (e.g. http://tuzehez-sensors.srv.mwn.de)

KEYCLOAK_SERVER_URL= (e.g. Keycloak URL http://tuzehez-sensors.srv.mwn.de:8080) 
KEYCLOAK_CLIENT_ID= (client ID registered in keycloak)
KEYCLOAK_USERNAME= (username created in keycloak)
KEYCLOAK_PASSWORD= (password created in keycloak)
KEYCLOAK_REALM= (e.g. master by default)

SMTP_SERVER=
SMTP_PORT=
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_ROOT_PASSWORD= (e.g Test@123 this will be default password when creating user afterwards user had to change it )

DATABASE_HOST=
DATABASE_USERNAME=
DATABASE_PASSWORD=
DATABASE_PORT=
DATABASE_NAME=

# FLUSK Service
SERVER_URL= (e.g http://tuzehez-sensors.srv.mwn.de:4500) 
```

```
sudo ufw allow in from any to any
sudo ufw allow out from any to any
```

  
The provided commands configure the firewall to allow all incoming and outgoing traffic on any port from any source or to any destination. This effectively opens up the firewall, allowing unrestricted communication to and from the system. This allows to allow traffic in created ports for NodeRED and FROST.

### Deploying sensorHUB_LITE

Create image from the docker file inside repository
```
docker build -t sensorhub_lite .

```

Running the container
```

docker run --network=sensorhub_lite -u root -d -p 4500:4500 --env-file .env --name sensorhub_lite_container  -v /var/run/docker.sock:/var/run/docker.sock --restart always sensorhub_lite ```
```
    


### Running Frontend

#### Cloning the Frontend From GitHub

    git clone https://github.com/HEFLoRa/WEB_APP.git


### Filling the ENV variables

Change directory to the `WEB_APP` folder

Creating a file `.env`
 
    REACT_APP_IS_DEVELOPMENT=true  # for LITE-version; when in PRO mode replace it with false
    REACT_APP_KEYCLOAK_URL=
    REACT_APP_KEYCLOAK_REALM=
    REACT_APP_KEYCLOAK_CLIENT_ID=
    REACT_APP_BACKEND_URL=
    REACT_APP_BACKEND_URL_ROOT=
    REACT_APP_GOOGLE_ANALYTICS_ID=

    
  #### Building the frontend
  

    docker build -t hefsensorhub_image_frontend .
    docker run -p 3000:3000 --env-file .env --name hefsensorhub_container_frontend -d --restart always hefsensorhub_image_frontend

-   `docker run`: This is the command to run a Docker container.
-   `-p 3000:3000`: This flag maps port 3000 on the host machine to port 3000 on the container. It establishes a communication bridge between the host and the container.
-   `--env-file .env`: This flag specifies an environment file (`.env`) to provide environment variables to the container. The file likely contains configuration settings needed by the frontend application.
-   `--name hefsensorhub_container_frontend`: This flag assigns the name "hefsensorhub_container_frontend" to the running container.
-   `-d`: This flag runs the container in detached mode, meaning it runs in the background.
-   `--restart always`: This flag ensures that the container restarts automatically if it stops unexpectedly.
-   `hefsensorhub_image_frontend`: This is the name of the Docker image to use for creating the container. It indicates that the container is based on the specified Docker image, presumably containing the frontend application.


Now the application should run on port `3000`.


## Authors

David Gackstetter, Parid Varoshi, Syed Saad Zahidi

Contact: david.gackstetter@tum.de


## License

Copyright (C) 2024 Technical University of Munich, Arcisstr. 11, 80333 Munich, Germany.

This program is free software: you can redistribute it and/or modify it under the terms of the CC-BY-4.0 License. You may copy, distribute, display, perform and make derivative works and remixes based on it, yet only if giving the author or licensor the credits (attribution) in the manner specified by these.  

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the CC-BY-4.0 License for more details.

You should have received a copy of the CC-BY-4.0 license along with this program.  If not, see https://creativecommons.org/licenses/by/4.0/.
