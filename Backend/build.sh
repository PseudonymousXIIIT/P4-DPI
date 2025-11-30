#!/bin/bash
# Build script for P4 DPI Tool

set -e

echo "Building P4 DPI Tool..."

# Create necessary directories
mkdir -p logs
mkdir -p p4_programs
mkdir -p scripts
mkdir -p config
mkdir -p tests

# Set permissions
chmod +x scripts/*.py

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Build Docker image
echo "Building Docker image..."
docker-compose build

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Docker image built successfully!"
else
    echo "Error: Docker image build failed."
    exit 1
fi

# Create a simple test script
cat > test_build.sh << 'EOF'
#!/bin/bash
# Test script to verify the build

echo "Testing P4 DPI Tool build..."

# Test Docker container
echo "Testing Docker container..."
docker-compose run --rm p4-dpi python3 -c "import sys; print('Python version:', sys.version)"

# Test P4 compiler
echo "Testing P4 compiler..."
docker-compose run --rm p4-dpi p4c --version

# Test Mininet
echo "Testing Mininet..."
docker-compose run --rm p4-dpi python3 -c "import mininet; print('Mininet imported successfully')"

echo "Build test completed successfully!"
EOF

chmod +x test_build.sh

echo "Build completed successfully!"
echo "To test the build, run: ./test_build.sh"
echo "To start the system, run: docker-compose up"
