#!/bin/bash
# Quick test script for Render deployment

echo "🧪 P4 DPI - Render Deployment Test"
echo "=================================="
echo ""

# Check if required files exist
echo "📁 Checking required files..."
files=("render.yaml" "Dockerfile.render" "api_server.py" "sync_to_render.py")
all_exist=true

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file (missing)"
        all_exist=false
    fi
done

if [ "$all_exist" = false ]; then
    echo ""
    echo "❌ Some required files are missing!"
    exit 1
fi

echo ""
echo "🐳 Building Docker image..."
if docker build -f Dockerfile.render -t p4-dpi-render-test . > /dev/null 2>&1; then
    echo "  ✓ Docker build successful"
else
    echo "  ✗ Docker build failed"
    echo "  Run: docker build -f Dockerfile.render -t p4-dpi-render-test ."
    exit 1
fi

echo ""
echo "🚀 Starting container on port 10000..."
docker run -d --name p4-dpi-render-test -p 10000:10000 p4-dpi-render-test > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "  ✓ Container started"
else
    echo "  ✗ Failed to start container"
    docker rm -f p4-dpi-render-test > /dev/null 2>&1
    exit 1
fi

echo ""
echo "⏳ Waiting for API to be ready (10 seconds)..."
sleep 10

echo ""
echo "🧪 Testing API endpoints..."

# Test health endpoint
response=$(curl -s http://localhost:10000/api/health)
if echo "$response" | grep -q "healthy"; then
    echo "  ✓ Health check passed"
else
    echo "  ✗ Health check failed"
    echo "  Response: $response"
fi

# Test root endpoint
response=$(curl -s http://localhost:10000/)
if echo "$response" | grep -q "P4 DPI API"; then
    echo "  ✓ Root endpoint working"
else
    echo "  ✗ Root endpoint failed"
fi

# Test stats endpoint
response=$(curl -s http://localhost:10000/api/stats)
if echo "$response" | grep -q "success"; then
    echo "  ✓ Stats endpoint working"
else
    echo "  ✗ Stats endpoint failed"
fi

echo ""
echo "🧹 Cleaning up..."
docker stop p4-dpi-render-test > /dev/null 2>&1
docker rm p4-dpi-render-test > /dev/null 2>&1
docker rmi p4-dpi-render-test > /dev/null 2>&1
echo "  ✓ Cleanup complete"

echo ""
echo "✅ All tests passed! Ready to deploy to Render."
echo ""
echo "Next steps:"
echo "  1. git add ."
echo "  2. git commit -m 'Add Render deployment'"
echo "  3. git push origin main"
echo "  4. Connect repo to Render dashboard"
echo ""
echo "📖 See DEPLOYMENT_SUMMARY.md for full instructions"
