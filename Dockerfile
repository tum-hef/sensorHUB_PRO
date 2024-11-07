# Use the official Python base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
# Install dnsutils for nsupdate and clean up after installation
RUN apt-get update && \
    apt-get install -y dnsutils && \
    rm -rf /var/lib/apt/lists/*

# Install sudo
RUN apt-get update && apt-get install -y sudo    

# Install Certbot
RUN apt-get update && apt-get install -y certbot



# Install Docker Compose
RUN curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x /usr/local/bin/docker-compose

# Install Docker CLI
RUN curl -fsSL https://get.docker.com -o get-docker.sh
RUN sh get-docker.sh

# Copy the requirements file to the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code to the container
COPY . .

# Expose the port the Flask app will run on
EXPOSE 4500

# Set the environment variable to use .env file in the root directory
ENV FLASK_ENV=development
ENV FLASK_APP=index.py

# Run the Flask application
CMD ["flask", "run", "--host=0.0.0.0", "--port=4500"]
