#!/bin/bash
# Script to build simple_switch_grpc in the container if it doesn't exist

if ! which simple_switch_grpc >/dev/null 2>&1; then
    echo "Building simple_switch_grpc..."
    
    # Check if bmv2 source exists
    if [ -d "/p4-dpi/bmv2" ]; then
        cd /p4-dpi/bmv2/targets/simple_switch_grpc
        make -j$(nproc) 2>&1 | tail -50
        if [ -f "simple_switch_grpc" ]; then
            cp simple_switch_grpc /usr/local/bin/
            chmod +x /usr/local/bin/simple_switch_grpc
            echo "SUCCESS: simple_switch_grpc installed"
        else
            echo "ERROR: Build failed"
            exit 1
        fi
    else
        echo "ERROR: BMv2 source directory not found. Please rebuild Docker image."
        exit 1
    fi
else
    echo "simple_switch_grpc already installed"
fi

