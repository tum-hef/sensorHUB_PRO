# Use the official Python base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y curl ldap-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Docker Compose
RUN curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x /usr/local/bin/docker-compose

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
