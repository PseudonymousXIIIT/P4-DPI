#!/bin/bash
# Run script for P4 DPI Tool

set -e

echo "Starting P4 DPI Tool..."

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "Error: Docker is not running. Please start Docker first."
    exit 1
fi

# Check if the Docker image exists
if ! docker images | grep -q "p4-dpi"; then
    echo "Docker image not found. Building..."
    ./build.sh
fi

# Start the system
echo "Starting P4 DPI system..."
docker-compose up -d

# Wait for the system to start
echo "Waiting for system to start..."
sleep 10

# Check if the container is running
if docker-compose ps | grep -q "Up"; then
    echo "P4 DPI system started successfully!"
    echo "Container is running. You can now:"
    echo "1. Access the web interface at http://localhost:5000"
    echo "2. View logs with: docker-compose logs -f"
    echo "3. Stop the system with: docker-compose down"
    echo "4. Access the container with: docker-compose exec p4-dpi bash"
else
    echo "Error: Failed to start the system."
    echo "Check logs with: docker-compose logs"
    exit 1
fi
