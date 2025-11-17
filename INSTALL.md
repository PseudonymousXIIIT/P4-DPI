# Installation Guide for P4 DPI Tool

This guide provides detailed installation instructions for the P4 Deep Packet Inspection tool.

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Prerequisites](#prerequisites)
3. [Installation Methods](#installation-methods)
4. [Configuration](#configuration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 10 GB free space
- **Network**: Ethernet interface with packet capture support
- **OS**: Linux (Ubuntu 20.04+ recommended)

### Recommended Requirements
- **CPU**: 4+ cores, 3.0+ GHz
- **RAM**: 8+ GB
- **Storage**: 50+ GB free space
- **Network**: Gigabit Ethernet interface
- **OS**: Ubuntu 22.04 LTS

### Supported Operating Systems
- Ubuntu 20.04+
- Ubuntu 22.04 LTS (Recommended)
- Debian 11+
- CentOS 8+
- RHEL 8+

## Prerequisites

### 1. Docker Installation

#### Ubuntu/Debian
```bash
# Update package index
sudo apt-get update

# Install required packages
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in for group changes to take effect
```

#### CentOS/RHEL
```bash
# Install required packages
sudo yum install -y yum-utils

# Add Docker repository
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker
sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
```

### 2. Docker Compose Installation

#### Ubuntu/Debian
```bash
# Install Docker Compose
sudo apt-get install -y docker-compose-plugin

# Verify installation
docker compose version
```

#### CentOS/RHEL
```bash
# Install Docker Compose
sudo yum install -y docker-compose-plugin

# Verify installation
docker compose version
```

### 3. Git Installation
```bash
# Ubuntu/Debian
sudo apt-get install -y git

# CentOS/RHEL
sudo yum install -y git
```

### 4. Network Configuration

#### Enable Packet Capture
```bash
# Install required packages
sudo apt-get install -y libpcap-dev tcpdump

# Enable packet capture on interface
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump
```

#### Configure Network Interfaces
```bash
# List network interfaces
ip link show

# Configure interface for promiscuous mode (if needed)
sudo ip link set dev eth0 promisc on
```

## Installation Methods

### Method 1: Docker Installation (Recommended)

#### 1. Clone the Repository
```bash
git clone <repository-url>
cd p4-dpi-tool
```

#### 2. Build the Docker Image
```bash
# Make build script executable
chmod +x build.sh

# Build the Docker image
./build.sh
```

#### 3. Start the System
```bash
# Make run script executable
chmod +x run.sh

# Start the system
./run.sh
```

### Method 2: Manual Installation

#### 1. Install P4 Tools
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
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
    libthrift-dev \
    libedit-dev \
    liblog4cxx-dev \
    libgc-dev \
    libgmp-dev \
    libpcap-dev \
    libboost-dev \
    libboost-test-dev \
    libboost-program-options-dev \
    libboost-filesystem-dev \
    libboost-thread-dev \
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
    libthrift-dev \
    libedit-dev \
    liblog4cxx-dev \
    libgc-dev

# Clone and build BMv2
git clone https://github.com/p4lang/behavioral-model.git bmv2
cd bmv2
git checkout 1.15.0
./autogen.sh
./configure --enable-debugger --with-pi
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..

# Clone and build P4 compiler
git clone https://github.com/p4lang/p4c.git
cd p4c
git checkout v1.2.4.2
git submodule update --init --recursive
mkdir build
cd build
cmake ..
make -j$(nproc)
sudo make install
sudo ldconfig
cd ../..

# Clone and build PI
git clone https://github.com/p4lang/PI.git
cd PI
git submodule update --init --recursive
./autogen.sh
./configure --with-proto
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..

# Clone and build P4Runtime Python bindings
git clone https://github.com/p4lang/p4runtime-shell.git
cd p4runtime-shell
pip3 install -r requirements.txt
sudo python3 setup.py install
cd ..
```

#### 2. Install Python Dependencies
```bash
# Install Python packages
pip3 install -r requirements.txt
```

#### 3. Install Mininet
```bash
# Install Mininet
git clone https://github.com/mininet/mininet.git
cd mininet
sudo ./util/install.sh -a
cd ..
```

#### 4. Compile P4 Program
```bash
# Compile the P4 program
p4c --target bmv2 --arch v1model --p4runtime-files p4_programs/dpi_l2_l4.p4info.txt p4_programs/dpi_l2_l4.p4
```

## Configuration

### 1. Basic Configuration

#### Edit Main Configuration
```bash
nano config/dpi_config.yaml
```

Key configuration options:
```yaml
switches:
  - name: s1
    device_id: 1
    grpc_port: 50051
    cpu_port: 255

logging:
  level: INFO
  file: logs/dpi.log

monitoring:
  enable_real_time: true
  log_interval: 1
  stats_interval: 10
```

#### Edit Traffic Configuration
```bash
nano config/traffic_config.yaml
```

#### Edit Logging Configuration
```bash
nano config/logging_config.yaml
```

### 2. Network Configuration

#### Configure Network Interfaces
```bash
# List available interfaces
ip link show

# Configure interface for monitoring
sudo ip link set dev eth0 promisc on
```

#### Configure Firewall Rules
```bash
# Allow required ports
sudo ufw allow 5000/tcp  # Web interface
sudo ufw allow 8080/tcp  # API
sudo ufw allow 9090/tcp  # P4Runtime
```

### 3. Docker Configuration

#### Edit Docker Compose File
```bash
nano docker-compose.yml
```

#### Edit Dockerfile
```bash
nano Dockerfile
```

## Verification

### 1. Test Docker Installation
```bash
# Test Docker
docker --version
docker-compose --version

# Test Docker daemon
docker run hello-world
```

### 2. Test P4 Tools
```bash
# Test P4 compiler
p4c --version

# Test BMv2
simple_switch --version
```

### 3. Test Python Dependencies
```bash
# Test Python packages
python3 -c "import scapy; print('Scapy OK')"
python3 -c "import mininet; print('Mininet OK')"
python3 -c "import p4runtime; print('P4Runtime OK')"
```

### 4. Test System Components
```bash
# Test traffic generator
python3 scripts/traffic_generator.py --mode test

# Test packet logger
python3 scripts/packet_logger.py

# Test P4 controller
python3 scripts/p4_controller.py --help
```

### 5. Test Full System
```bash
# Start the system
python3 scripts/start_dpi.py

# In another terminal, generate traffic
python3 scripts/traffic_generator.py --mode generate --duration 60

# Check logs
tail -f logs/dpi.log
```

## Troubleshooting

### Common Issues

#### 1. Docker Build Fails
```bash
# Check Docker version
docker --version

# Clean Docker cache
docker system prune -a

# Check available disk space
df -h

# Rebuild with verbose output
docker-compose build --no-cache --progress=plain
```

#### 2. P4 Compilation Errors
```bash
# Check P4 compiler installation
which p4c
p4c --version

# Check P4 program syntax
p4c --target bmv2 --arch v1model --std p4_16 p4_programs/dpi_l2_l4.p4

# Check for missing dependencies
ldd /usr/local/bin/p4c
```

#### 3. Mininet Issues
```bash
# Check Mininet installation
python3 -c "import mininet"

# Check network namespaces
sudo ip netns list

# Clean up Mininet
sudo mn -c
```

#### 4. Network Connectivity Issues
```bash
# Check network interfaces
ip link show

# Check routing table
ip route show

# Test connectivity
ping 8.8.8.8

# Check packet capture permissions
sudo tcpdump -i any -c 1
```

#### 5. Permission Issues
```bash
# Check file permissions
ls -la scripts/

# Fix permissions
chmod +x scripts/*.py
chmod +x *.sh

# Check Docker group membership
groups $USER
```

#### 6. Memory Issues
```bash
# Check available memory
free -h

# Check swap usage
swapon -s

# Increase swap if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Debug Mode

#### Enable Debug Logging
```yaml
# In config/dpi_config.yaml
logging:
  level: DEBUG
```

#### Run with Verbose Output
```bash
# Docker
docker-compose up --build

# Python scripts
python3 -v scripts/start_dpi.py
```

#### Check System Logs
```bash
# Docker logs
docker-compose logs -f

# System logs
journalctl -u docker
dmesg | tail
```

### Performance Issues

#### Monitor System Resources
```bash
# CPU usage
top
htop

# Memory usage
free -h
cat /proc/meminfo

# Disk usage
df -h
du -sh logs/

# Network usage
iftop
nethogs
```

#### Optimize Configuration
```yaml
# Reduce memory usage
performance:
  memory:
    max_packets_in_memory: 10000
    cleanup_interval: 60

# Reduce logging
logging:
  level: WARNING
  max_size: 1048576
```

### Getting Help

#### Check Documentation
- README.md: Main documentation
- Code comments: Inline documentation
- Configuration files: Self-documenting

#### Community Support
- GitHub Issues: Report bugs and request features
- Discussion Forums: Community support
- Documentation Wiki: Additional resources

#### Professional Support
- Contact the development team
- Enterprise support options
- Training and consulting services

## Next Steps

After successful installation:

1. **Read the README.md** for usage instructions
2. **Configure the system** according to your needs
3. **Run the test suite** to verify functionality
4. **Start monitoring** your network traffic
5. **Customize** the system for your specific requirements

## Uninstallation

### Docker Installation
```bash
# Stop and remove containers
docker-compose down

# Remove images
docker-compose down --rmi all

# Remove volumes
docker-compose down -v

# Clean up
docker system prune -a
```

### Manual Installation
```bash
# Remove P4 tools
sudo rm -rf /usr/local/bin/p4c
sudo rm -rf /usr/local/bin/simple_switch*

# Remove Python packages
pip3 uninstall -r requirements.txt

# Remove Mininet
sudo rm -rf /usr/local/bin/mn
sudo rm -rf /usr/local/lib/python3.*/site-packages/mininet*

# Remove project files
rm -rf p4-dpi-tool
```
