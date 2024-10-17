
# sensorHUB - Lite Version
The sensorHUB software is a novel, open-source software stack for enhanced accessibility and secure interoperability in IoT project management. It is developed by Technical University of Munich's (TUM) Hans Eisenmann-Forum for Agricultural Sciences (HEF). For more background details see https://github.com/tum-hef/sensorHUB/.

This repository presents the sensorHUB's Lite version, which in contrast to the Pro version (provided in a separate repository: https://github.com/HEFLoRa/sensorHUB_PRO) is only based on HTTP-network communication without operationally oriented domain-specific adresses and SSL-enhancement. 


## Conceptual Overview
The sensorHUB technology stack comprises the following components:

1.  **Keycloak** for authentication and overall application security, serving as the top layer that protects NodeRED, Frontend, Backend, FROST-server, and MySQL.
    
2.  **Frontend** developed using React with Typescript, serving as the web application. Upon user authentication, it can connect to the Node-RED page.
    
3.  **Backend** implemented in Python using Flask, providing functionalities such as user registration, various procedures linked to FROST-server, email sending, and log tracking.
        
4.  **FROST-server** is utilized for specific procedures within the backend, contributing to the overall capabilities of the system.
    
5.  **MySQL** serves as the database, tracking user registrations, verifications, and error logs.

6.  **NodeRED**, integrated into the stack, enhances the overall functionality and connectivity of the application.


![iot_stack_concept_finals2](https://github.com/user-attachments/assets/193af270-2ce4-46eb-857d-b68b87c6632f)

## Changes and Updates

See the [Change Log](CHANGELOG.md).

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create.
Any contributions are greatly appreciated.
You can read more in our [contribution guidelines](CONTRIBUTING.md).

## Compiling

### Running Keycloak 

  #### Installing Keycloak and running it from docker

     docker run -d --name keycloak --restart=always -p 8080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin -e PROXY_ADDRESS_FORWARDING=true jboss/keycloak
-   `docker run`: This is the command to run a Docker container.
-   `-d`: This flag stands for "detached" mode, which means the container runs in the background.
-   `--name keycloak`: This flag assigns the name "keycloak" to the running container.
-   `--restart always`: This flag ensures that the container automatically restarts if it stops unexpectedly.
-   `-p 8080:8080`: This flag maps port 8080 on the host machine to port 8080 on the container. Port 8080 is typically used for accessing Keycloak's web interface.
-   `-e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin`: These environment variables set the username and password for the initial Keycloak administrator account. In this case, the username is "admin" and the password is also "admin."
-   `-e PROXY_ADDRESS_FORWARDING=true`: This environment variable is set to "true" and is related to handling proxy address forwarding. It is often used when Keycloak is running behind a reverse proxy.
-   `jboss/keycloak`: This is the name of the Docker image that will be used to create the container. It specifies the official Keycloak Docker image provided by the JBoss organization.


  
The provided Docker command runs a Keycloak container in detached mode, naming it "keycloak," ensuring automatic restarts, mapping host port 8080 to the container's port 8080, setting the initial admin credentials to admin/admin (**for security purpose, please change the default password**), and enabling proxy address forwarding. The container is based on the official Keycloak Docker image (`jboss/keycloak`).

#### Removing HTTPs (Optional and NOT recommended)

`contaierID` - container ID of the keycloak

    docker exec -it {contaierID} bash
    cd /opt/jboss/keycloak/bin
    ./kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user admin
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

    git clone https://github.com/HEFLoRa/KEYCLOAK_SERVICES

    cd KEYCLOAK_SERVICES
  
    
Run the Initial queries  `KEYCLOAK_SERVICES/initial_queries.sql` on the DB instance you created.

Inside the the KEYCLOAK_SERVICES folder, create a new file `.env` for env variables, you also follow `.env example`

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

    docker build -t hefsensorhub_image_backend .
    docker run -d -p 4500:4500 --env-file .env --name HEFsensorHUB_container_backend -v /var/run/docker.sock:/var/run/docker.sock --restart always hefsensorhub_image_backend

  
The first command builds a Docker image named `hefsensorhub_image_backend` from the Dockerfile in the current directory. The second command runs a detached Docker container named `HEFsensorHUB_container_backend` based on the `hefsensorhub_image_backend` image, mapping port 4500, using environment variables from a file (`.env`), and allowing interaction with the host's Docker daemon through a volume mount. The container restarts automatically.


### Running Frontend

#### Cloning the Frontend From GitHub

    git clone https://github.com/HEFLoRa/WEB_APP.git


### Filling the ENV variables

Change directory to the `WEB_APP` folder

Creating a file `.env`

	
    REACT_APP_KEYCLOAK_URL=
    REACT_APP_KEYCLOAK_REALM=
    REACT_APP_KEYCLOAK_CLIENT_ID=
    REACT_APP_BACKEND_URL=
    REACT_APP_BACKEND_URL_ROOT=
    REACT_APP_GOOGLE_ANALYTICS_ID=

    
  #### Building the frontend
  

    docker build -t hefsensorhub_image_frontend .
    docker run -p 3000:80 --env-file .env --name hefsensorhub_container_frontend -d --restart always hefsensorhub_image_frontend

-   `docker run`: This is the command to run a Docker container.
-   `-p 3000:80`: This flag maps port 3000 on the host machine to port 80 on the container. It establishes a communication bridge between the host and the container.
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

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
