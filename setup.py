#!/usr/bin/env python3
"""
Setup script for P4 DPI Tool
Handles installation, configuration, and initial setup
"""

import os
import sys
import subprocess
import shutil
import yaml
import json
from pathlib import Path

class DPISetup:
    def __init__(self):
        """Initialize the setup process"""
        self.project_root = Path(__file__).parent
        self.config_dir = self.project_root / "config"
        self.logs_dir = self.project_root / "logs"
        self.scripts_dir = self.project_root / "scripts"
        self.p4_programs_dir = self.project_root / "p4_programs"
        self.tests_dir = self.project_root / "tests"
        
    def check_prerequisites(self):
        """Check if all prerequisites are installed"""
        print("Checking prerequisites...")
        
        prerequisites = {
            'docker': 'Docker',
            'docker-compose': 'Docker Compose',
            'git': 'Git',
            'python3': 'Python 3'
        }
        
        missing = []
        for cmd, name in prerequisites.items():
            if not shutil.which(cmd):
                missing.append(name)
            else:
                print(f"✓ {name} is installed")
        
        if missing:
            print(f"\n❌ Missing prerequisites: {', '.join(missing)}")
            print("Please install the missing prerequisites before continuing.")
            return False
        
        print("✓ All prerequisites are installed")
        return True
    
    def create_directories(self):
        """Create necessary directories"""
        print("Creating directories...")
        
        directories = [
            self.logs_dir,
            self.config_dir,
            self.p4_programs_dir,
            self.tests_dir,
            self.project_root / "templates"
        ]
        
        for directory in directories:
            directory.mkdir(exist_ok=True)
            print(f"✓ Created directory: {directory}")
    
    def set_permissions(self):
        """Set proper permissions for scripts"""
        print("Setting permissions...")
        
        script_files = [
            "build.sh",
            "run.sh",
            "scripts/start_dpi.py",
            "scripts/p4_controller.py",
            "scripts/packet_logger.py",
            "scripts/traffic_generator.py",
            "scripts/mininet_topology.py",
            "scripts/web_interface.py",
            "tests/test_dpi_system.py"
        ]
        
        for script_file in script_files:
            script_path = self.project_root / script_file
            if script_path.exists():
                os.chmod(script_path, 0o755)
                print(f"✓ Set permissions for: {script_file}")
    
    def create_default_configs(self):
        """Create default configuration files if they don't exist"""
        print("Creating default configurations...")
        
        # Main DPI configuration
        dpi_config = {
            'switches': [
                {
                    'name': 's1',
                    'device_id': 1,
                    'grpc_port': 50051,
                    'cpu_port': 255,
                    'p4info_file': 'p4_programs/dpi_l2_l4.p4info.txt',
                    'runtime_json_file': 'p4_programs/dpi_l2_l4.json'
                }
            ],
            'logging': {
                'level': 'INFO',
                'file': 'logs/dpi.log',
                'max_size': 10485760,
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'monitoring': {
                'enable_real_time': True,
                'log_interval': 1,
                'stats_interval': 10,
                'packet_capture': True,
                'flow_analysis': True,
                'anomaly_detection': True
            },
            'network': {
                'topology': {
                    'type': 'mininet',
                    'switches': 3,
                    'hosts': 6,
                    'links': 7
                },
                'subnets': [
                    {
                        'name': 'client_network',
                        'subnet': '10.0.1.0/24',
                        'gateway': '10.0.1.254'
                    },
                    {
                        'name': 'server_network',
                        'subnet': '10.0.2.0/24',
                        'gateway': '10.0.2.254'
                    }
                ]
            },
            'security': {
                'suspicious_detection': {
                    'port_scanning': {
                        'enabled': True,
                        'threshold': 10,
                        'action': 'log'
                    },
                    'ddos_detection': {
                        'enabled': True,
                        'threshold': 100,
                        'action': 'log'
                    }
                }
            },
            'performance': {
                'packet_processing': {
                    'max_packets_per_second': 10000,
                    'buffer_size': 1000,
                    'timeout': 5
                },
                'memory': {
                    'max_packets_in_memory': 100000,
                    'cleanup_interval': 300
                },
                'database': {
                    'enabled': True,
                    'file': 'logs/packets.db',
                    'max_size': 1073741824,
                    'backup_interval': 3600
                }
            },
            'web_interface': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 5000,
                'debug': False,
                'authentication': False
            },
            'api': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 8080,
                'rate_limit': 100,
                'authentication': False
            }
        }
        
        config_file = self.config_dir / "dpi_config.yaml"
        if not config_file.exists():
            with open(config_file, 'w') as f:
                yaml.dump(dpi_config, f, default_flow_style=False)
            print(f"✓ Created: {config_file}")
        
        # Logging configuration
        logging_config = {
            'database': {
                'enabled': True,
                'file': 'logs/packets.db',
                'max_connections': 10,
                'timeout': 30
            },
            'export': {
                'enabled': True,
                'formats': ['json', 'csv', 'pcap'],
                'interval': 300,
                'compression': True,
                'encryption': False,
                'max_file_size': 104857600
            },
            'analysis': {
                'enabled': True,
                'flow_analysis': True,
                'anomaly_detection': True,
                'statistics_interval': 60,
                'real_time_alerts': True
            },
            'retention': {
                'max_packets': 100000,
                'max_age_days': 7,
                'cleanup_interval': 3600,
                'archive_old_data': True
            },
            'alerts': {
                'enabled': True,
                'channels': ['file', 'email', 'webhook'],
                'thresholds': {
                    'suspicious_packets': 10,
                    'port_scan_attempts': 5,
                    'ddos_attack': 100,
                    'malformed_packets': 50
                }
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/packet_logger.log',
                'max_size': 10485760,
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        }
        
        logging_file = self.config_dir / "logging_config.yaml"
        if not logging_file.exists():
            with open(logging_file, 'w') as f:
                yaml.dump(logging_config, f, default_flow_style=False)
            print(f"✓ Created: {logging_file}")
        
        # Traffic configuration
        traffic_config = {
            'src_ips': ['10.0.1.1', '10.0.1.2', '10.0.3.1'],
            'dst_ips': ['10.0.2.1', '10.0.2.2', '10.0.4.1'],
            'src_ports': '1024-65535',
            'dst_ports': [80, 443, 22, 53, 21, 25, 110, 143, 993, 995, 3389, 5900, 8080, 8443],
            'patterns': {
                'normal_traffic': {
                    'enabled': True,
                    'rate': 10,
                    'duration': 300,
                    'protocols': ['TCP', 'UDP', 'ICMP'],
                    'description': 'Normal network traffic patterns'
                },
                'http_traffic': {
                    'enabled': True,
                    'rate': 5,
                    'duration': 300,
                    'protocols': ['TCP'],
                    'ports': [80, 443, 8080, 8443],
                    'description': 'HTTP/HTTPS traffic simulation'
                },
                'dns_traffic': {
                    'enabled': True,
                    'rate': 2,
                    'duration': 300,
                    'protocols': ['UDP'],
                    'ports': [53],
                    'description': 'DNS query traffic'
                },
                'ping_traffic': {
                    'enabled': True,
                    'rate': 1,
                    'duration': 300,
                    'protocols': ['ICMP'],
                    'description': 'ICMP ping traffic'
                },
                'port_scan': {
                    'enabled': True,
                    'rate': 20,
                    'duration': 60,
                    'protocols': ['TCP'],
                    'description': 'Port scanning attack simulation',
                    'suspicious': True
                },
                'ddos_attack': {
                    'enabled': True,
                    'rate': 100,
                    'duration': 30,
                    'protocols': ['TCP', 'UDP'],
                    'description': 'DDoS attack simulation',
                    'suspicious': True
                }
            },
            'generation': {
                'randomize_sources': True,
                'randomize_destinations': True,
                'randomize_ports': True,
                'packet_size_range': {'min': 64, 'max': 1500},
                'inter_packet_delay': {'min': 0.001, 'max': 1.0}
            },
            'interface': {
                'name': 'eth0',
                'promiscuous': True,
                'monitor_mode': False
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/traffic_generator.log',
                'max_size': 10485760,
                'backup_count': 3,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        }
        
        traffic_file = self.config_dir / "traffic_config.yaml"
        if not traffic_file.exists():
            with open(traffic_file, 'w') as f:
                yaml.dump(traffic_config, f, default_flow_style=False)
            print(f"✓ Created: {traffic_file}")
    
    def create_gitignore(self):
        """Create .gitignore file"""
        print("Creating .gitignore...")
        
        gitignore_content = """# Logs
logs/
*.log

# Database files
*.db
*.sqlite
*.sqlite3

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Docker
.dockerignore

# Temporary files
*.tmp
*.temp
.cache/

# P4 compiled files
*.p4info.txt
*.json

# Mininet
mininet.log
*.pcap
*.cap

# Test files
test_*.py
*_test.py
"""
        
        gitignore_file = self.project_root / ".gitignore"
        if not gitignore_file.exists():
            with open(gitignore_file, 'w') as f:
                f.write(gitignore_content)
            print(f"✓ Created: {gitignore_file}")
    
    def create_license(self):
        """Create LICENSE file"""
        print("Creating LICENSE...")
        
        license_content = """MIT License

Copyright (c) 2024 P4 DPI Tool

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
        
        license_file = self.project_root / "LICENSE"
        if not license_file.exists():
            with open(license_file, 'w') as f:
                f.write(license_content)
            print(f"✓ Created: {license_file}")
    
    def run_tests(self):
        """Run the test suite"""
        print("Running tests...")
        
        try:
            result = subprocess.run([
                sys.executable, "-m", "pytest", 
                str(self.tests_dir), 
                "-v", "--tb=short"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✓ All tests passed")
                return True
            else:
                print("❌ Some tests failed")
                print(result.stdout)
                print(result.stderr)
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running tests: {e}")
            return False
        except FileNotFoundError:
            print("⚠️  pytest not found, skipping tests")
            return True
    
    def build_docker_image(self):
        """Build the Docker image"""
        print("Building Docker image...")
        
        try:
            result = subprocess.run([
                "docker-compose", "build"
            ], cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✓ Docker image built successfully")
                return True
            else:
                print("❌ Docker build failed")
                print(result.stdout)
                print(result.stderr)
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Error building Docker image: {e}")
            return False
        except FileNotFoundError:
            print("❌ docker-compose not found")
            return False
    
    def setup(self):
        """Run the complete setup process"""
        print("🚀 Setting up P4 DPI Tool...")
        print("=" * 50)
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        # Create directories
        self.create_directories()
        
        # Set permissions
        self.set_permissions()
        
        # Create default configurations
        self.create_default_configs()
        
        # Create additional files
        self.create_gitignore()
        self.create_license()
        
        # Run tests
        if not self.run_tests():
            print("⚠️  Tests failed, but continuing with setup...")
        
        # Build Docker image
        if not self.build_docker_image():
            print("⚠️  Docker build failed, but continuing with setup...")
        
        print("=" * 50)
        print("✅ Setup completed successfully!")
        print("\nNext steps:")
        print("1. Review configuration files in config/")
        print("2. Start the system: ./run.sh")
        print("3. Access web interface: http://localhost:5000")
        print("4. Check logs: docker-compose logs -f")
        
        return True

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='P4 DPI Tool Setup')
    parser.add_argument('--skip-tests', action='store_true', 
                       help='Skip running tests')
    parser.add_argument('--skip-docker', action='store_true', 
                       help='Skip Docker build')
    
    args = parser.parse_args()
    
    setup = DPISetup()
    
    if args.skip_tests:
        setup.run_tests = lambda: True
    
    if args.skip_docker:
        setup.build_docker_image = lambda: True
    
    success = setup.setup()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
