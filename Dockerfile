# P4 DPI Tool Dockerfile
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    libffi-dev \
    python3 \
    python3-pip \
    python3-dev \
    libreadline-dev \
    libncurses5-dev \
    libncursesw5-dev \
    zlib1g-dev \
    libbz2-dev \
    libsqlite3-dev \
    liblzma-dev \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libffi-dev \
    liblzma-dev \
    autoconf \
    automake \
    libtool \
    make \
    g++ \
    flex \
    bison \
    libpcap-dev \
    libboost-dev \
    libboost-test-dev \
    libboost-program-options-dev \
    libboost-filesystem-dev \
    libboost-thread-dev \
    libboost-iostreams-dev \
    libevent-dev \
    libprotobuf-dev \
    protobuf-compiler \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    libnanomsg-dev \
    libjudy-dev \
    libgmp-dev \
    libpciaccess-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev \
    libnl-3-dev \
    pkg-config \
    libsystemd-dev \
    libedit-dev \
    liblog4cxx-dev \
    libgc-dev \
    libelf-dev \
    iputils-ping \
    thrift-compiler \
    libthrift-dev \
    help2man \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --upgrade pip
RUN pip3 install \
    scapy \
    psutil \
    grpcio \
    grpcio-tools \
    protobuf \
    p4runtime \
    ipaddress \
    netaddr \
    colorama \
    termcolor \
    tabulate \
    pandas \
    pyyaml \
    requests \
    flask \
    flask-cors

# Build Mininet from source to get all binaries (mnexec, etc.)
RUN git clone https://github.com/mininet/mininet.git && \
    cd mininet && \
    git checkout 2.3.0 && \
    PYTHON=python3 make install && \
    cd .. && rm -rf mininet

# Set working directory
WORKDIR /p4-dpi

# Clone and build PI (P4Runtime) first - required by BMv2
RUN git clone https://github.com/p4lang/PI.git && \
    cd PI && \
    git submodule update --init --recursive && \
    ./autogen.sh && \
    ./configure --with-proto && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Clone and build P4 tools (BMv2) in explicit steps for clearer failures and better caching
RUN git clone https://github.com/p4lang/behavioral-model.git bmv2 && \
    cd bmv2 && \
    git checkout 1.15.0 && \
    ./autogen.sh && \
    ./configure --enable-debugger --with-pi && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build simple_switch_grpc separately to avoid running fallback commands in the wrong directory
RUN cd bmv2/targets/simple_switch_grpc && \
    # Attempt normal build; if it fails try re-running autogen/configure in this subdir
    (make -j$(nproc)) || (./autogen.sh && ./configure --with-pi && make -j$(nproc)) && \
    if [ -f simple_switch_grpc ]; then \
        cp simple_switch_grpc /usr/local/bin/ && chmod +x /usr/local/bin/simple_switch_grpc && echo "SUCCESS: simple_switch_grpc installed"; \
    elif [ -f .libs/simple_switch_grpc ]; then \
        cp .libs/simple_switch_grpc /usr/local/bin/ && chmod +x /usr/local/bin/simple_switch_grpc && echo "SUCCESS: simple_switch_grpc installed from .libs"; \
    else \
        echo "WARNING: simple_switch_grpc not found after build"; \
    fi

# Clone and build P4 compiler from main branch (with retry for network issues)
# Use shallow clone to reduce network issues
RUN (git clone --depth 1 https://github.com/p4lang/p4c.git || \
    (sleep 10 && git clone --depth 1 https://github.com/p4lang/p4c.git)) && \
    cd p4c && \
    git checkout main || git fetch --unshallow && git checkout main && \
    (git submodule update --init --recursive --depth 1 || \
    (sleep 10 && git submodule update --init --recursive --depth 1)) && \
    mkdir build && \
    cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release \
             -DENABLE_BMV2=ON \
             -DENABLE_EBPF=OFF \
             -DENABLE_UBPF=OFF \
             -DENABLE_DPDK=OFF \
             -DENABLE_P4C_GRAPHS=OFF \
             -DENABLE_TESTS=OFF && \
    make -j2 && \
    make install && \
    ldconfig

# Install P4Runtime shell (Python) directly from Git
RUN pip3 install --no-cache-dir git+https://github.com/p4lang/p4runtime-shell.git

# Install Flask and other Python dependencies for API
RUN pip3 install --no-cache-dir \
    flask>=2.0.0 \
    flask-cors>=3.0.10 \
    gunicorn>=20.1.0

# Copy project files
COPY . /p4-dpi/

# Set environment variables
ENV P4C=/usr/local/bin/p4c
ENV BMV2=/usr/local
ENV PYTHONPATH=/usr/local/lib/python3.8/site-packages:$PYTHONPATH

# Create logs directory
RUN mkdir -p /p4-dpi/logs

# Expose ports: 5000 (Flask API), 8080 (Mininet), 9090 (BMv2), 10000 (Gunicorn/Render)
EXPOSE 5000 8080 9090 10000

# Set working directory
WORKDIR /p4-dpi

# Startup script that runs both P4 DPI and Flask API
RUN echo '#!/bin/bash\n\
set -e\n\
echo "Starting P4 DPI system..."\n\
export DPI_TRAFFIC_TARGET_PACKETS=${DPI_TRAFFIC_TARGET_PACKETS:-600}\n\
\n\
# Run P4 DPI in background\n\
python3 scripts/start_dpi.py --mode start &\n\
DPI_PID=$!\n\
\n\
echo "P4 DPI started (PID: $DPI_PID)"\n\
sleep 10\n\
\n\
# Run Flask API with Gunicorn on dynamic Render port\n\
echo "Starting Flask API..."\n\
cd /p4-dpi\n\
gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120 --worker-class sync --access-logfile - --error-logfile - scripts.flask_api:app\n\
' > /startup.sh && chmod +x /startup.sh

# Use startup script as entrypoint
CMD ["/startup.sh"]
