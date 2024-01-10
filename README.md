# HEF-sensorHUB


## Technology Stack of HEF-sensorHUB

  
The sensorHUB technology stack comprises the following components:

1.  Keycloak for authentication and overall application security, serving as the top layer that protects NodeRED, Frontend, Backend, FROST-server, and MySQL.
    
2.  Frontend developed using React with Typescript, serving as the web application. Upon user authentication, it can connect to the Node-RED page.
    
3.  Backend implemented in Python using Flask, providing functionalities such as user registration, various procedures linked to FROST-server, email sending, and log tracking.
    
4.  NodeRED, integrated into the stack, enhances the overall functionality and connectivity of the application.
    
5.  FROST-server is utilized for specific procedures within the backend, contributing to the overall capabilities of the system.
    
6.  MySQL serves as the database, tracking user registrations, verifications, and error logs.

![Tech-Stack](https://github.com/HEFLoRa/HEF-sensorHUB/assets/49834648/a24b787e-0dea-4954-ad78-5445d0514f8b)



## Running Keycloak 

  ### Installing Keycloak and running it from docker

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

### Removing HTTPs (Optional and NOT recommended)

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
