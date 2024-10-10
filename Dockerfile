# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project to the container
COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Set environment variables for production
ENV FLASK_SECRET_KEY="your_secret_key_here"
ENV JWT_SECRET_KEY="your_jwt_secret_key_here"
ENV FLASK_ENV="production"

# Command to run the application
CMD ["waitress-serve", "--host", "0.0.0.0", "--port", "5000", "main:app"]
