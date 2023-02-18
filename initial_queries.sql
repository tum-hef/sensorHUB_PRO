CREATE DATABASE IF NOT EXISTS tumservices;
use tumservices;
CREATE TABLE user_registered (
  ID int AUTO_INCREMENT PRIMARY KEY,
  firstName varchar(255) NOT NULL,
  lastName varchar(255) NOT NULL,
  email varchar(255) NOT NULL,
  token varchar(255) NOT NULL,
  isVerified boolean DEFAULT false,
  isCompleted boolean DEFAULT false,
  createdAt timestamp DEFAULT CURRENT_TIMESTAMP,
  completedAt timestamp DEFAULT NULL
);