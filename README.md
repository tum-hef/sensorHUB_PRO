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
