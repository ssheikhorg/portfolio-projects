# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables for Redis
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379
ENV REDIS_DB=0

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file into the container at /app
COPY ./requirements.txt /app

# Install any needed dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt python-multipart uvicorn

# Copy the src directory into the container at /app/src
COPY ./src /app/src

# Expose the port where the FastAPI app will run
EXPOSE 8000

# Command to run the FastAPI application using Uvicorn server
CMD ["uvicorn", "src.Api_Endpoints:app", "--host", "0.0.0.0", "--port", "8000"]
