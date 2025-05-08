# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libcairo2-dev \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy only the necessary files first to leverage Docker cache
# COPY requirements.txt .

# Install dependencies
# RUN pip install --no-cache-dir -r requirements.txt
RUN pip install fastapi[all] psycopg[binary,pool] supabase sqlmodel pyjwt web3 zksync2 eth_keys eth_utils eth_account apscheduler
# Copy the entire application
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose the FastAPI port
EXPOSE 10001

# Start the FastAPI application
CMD ["fastapi", "dev","--host", "0.0.0.0", "--port", "10001"]
