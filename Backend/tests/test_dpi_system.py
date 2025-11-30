#!/usr/bin/env python3
"""
Test suite for P4 DPI Tool
Comprehensive testing of all system components
"""

import unittest
import os
import sys
import time
import json
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
import sqlite3
import yaml

# Add project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.p4_controller import DPIController
from scripts.packet_logger import PacketLogger, PacketInfo
from scripts.traffic_generator import TrafficGenerator
from scripts.web_interface import DPIWebInterface

class TestDPIController(unittest.TestCase):
    """Test cases for DPI Controller"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_config.yaml')
        
        # Create test configuration
        test_config = {
            'switches': [
                {
                    'name': 's1',
                    'device_id': 1,
                    'grpc_port': 50051,
                    'cpu_port': 255
                }
            ],
            'logging': {
                'level': 'INFO',
                'file': os.path.join(self.temp_dir, 'test.log')
            },
            'monitoring': {
                'enable_real_time': True,
                'log_interval': 1,
                'stats_interval': 10
            }
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(test_config, f)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    @patch('scripts.p4_controller.p4runtime_lib.simple_controller.SimpleSwitch')
    def test_controller_initialization(self, mock_switch):
        """Test controller initialization"""
        controller = DPIController(self.config_file)
        
        self.assertIsNotNone(controller.config)
        self.assertIsNotNone(controller.logger)
        self.assertEqual(len(controller.switches), 0)
        self.assertFalse(controller.running)
    
    def test_config_loading(self):
        """Test configuration loading"""
        controller = DPIController(self.config_file)
        
        self.assertIn('switches', controller.config)
        self.assertIn('logging', controller.config)
        self.assertIn('monitoring', controller.config)
    
    def test_default_config(self):
        """Test default configuration when file doesn't exist"""
        non_existent_config = os.path.join(self.temp_dir, 'non_existent.yaml')
        controller = DPIController(non_existent_config)
        
        self.assertIsNotNone(controller.config)
        self.assertIn('switches', controller.config)

class TestPacketLogger(unittest.TestCase):
    """Test cases for Packet Logger"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'logging_config.yaml')
        
        # Create test configuration
        test_config = {
            'database': {
                'enabled': True,
                'file': os.path.join(self.temp_dir, 'test.db')
            },
            'export': {
                'enabled': True,
                'formats': ['json', 'csv'],
                'interval': 60
            },
            'analysis': {
                'enabled': True,
                'flow_analysis': True,
                'anomaly_detection': True,
                'statistics_interval': 30
            },
            'retention': {
                'max_packets': 1000,
                'max_age_days': 1
            }
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(test_config, f)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_logger_initialization(self):
        """Test packet logger initialization"""
        logger = PacketLogger(self.config_file)
        
        self.assertIsNotNone(logger.config)
        self.assertIsNotNone(logger.logger)
        self.assertEqual(len(logger.packets), 0)
        self.assertIsNotNone(logger.stats)
    
    def test_packet_info_creation(self):
        """Test PacketInfo data class"""
        packet_info = PacketInfo(
            timestamp='2024-01-15T10:30:45',
            switch_id='s1',
            src_mac='00:00:00:00:00:01',
            dst_mac='00:00:00:00:00:02',
            src_ip='10.0.1.1',
            dst_ip='10.0.2.1',
            src_port=12345,
            dst_port=80,
            protocol='TCP',
            packet_size=64,
            tcp_flags=2,
            icmp_type=0,
            icmp_code=0,
            is_fragment=False,
            is_malformed=False,
            is_suspicious=False,
            layer2_protocol='Ethernet',
            layer3_protocol='IPv4',
            layer4_protocol='TCP',
            ttl=64,
            tos=0,
            flow_id='test_flow'
        )
        
        self.assertEqual(packet_info.src_ip, '10.0.1.1')
        self.assertEqual(packet_info.dst_ip, '10.0.2.1')
        self.assertEqual(packet_info.protocol, 'TCP')
    
    def test_flow_id_generation(self):
        """Test flow ID generation"""
        logger = PacketLogger(self.config_file)
        
        packet_data = {
            'src_ip': '10.0.1.1',
            'dst_ip': '10.0.2.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP'
        }
        
        flow_id = logger.generate_flow_id(packet_data)
        self.assertIsInstance(flow_id, str)
        self.assertIn('10.0.1.1', flow_id)
        self.assertIn('10.0.2.1', flow_id)
    
    def test_packet_logging(self):
        """Test packet logging functionality"""
        logger = PacketLogger(self.config_file)
        
        packet_data = {
            'switch_id': 's1',
            'src_mac': '00:00:00:00:00:01',
            'dst_mac': '00:00:00:00:00:02',
            'src_ip': '10.0.1.1',
            'dst_ip': '10.0.2.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 64,
            'tcp_flags': 2,
            'layer2_protocol': 'Ethernet',
            'layer3_protocol': 'IPv4',
            'layer4_protocol': 'TCP'
        }
        
        initial_count = len(logger.packets)
        logger.log_packet(packet_data)
        
        self.assertEqual(len(logger.packets), initial_count + 1)
        self.assertGreater(logger.stats['total_packets'], 0)
    
    def test_anomaly_detection(self):
        """Test anomaly detection"""
        logger = PacketLogger(self.config_file)
        
        # Test port scanning detection
        packet_data = {
            'src_ip': '10.0.1.1',
            'dst_ip': '10.0.2.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 64
        }
        
        # Simulate port scanning by logging many packets with different ports
        for port in range(80, 90):
            packet_data['dst_port'] = port
            logger.log_packet(packet_data)
        
        # Check if port scanning was detected
        self.assertGreater(logger.stats.get('suspicious_packets', 0), 0)
    
    def test_database_operations(self):
        """Test database operations"""
        logger = PacketLogger(self.config_file)
        
        # Test database creation
        self.assertTrue(os.path.exists(logger.config['database']['file']))
        
        # Test packet storage
        packet_data = {
            'switch_id': 's1',
            'src_ip': '10.0.1.1',
            'dst_ip': '10.0.2.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 64
        }
        
        logger.log_packet(packet_data)
        
        # Verify packet was stored in database
        conn = sqlite3.connect(logger.config['database']['file'])
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM packets')
        count = cursor.fetchone()[0]
        conn.close()
        
        self.assertGreater(count, 0)

class TestTrafficGenerator(unittest.TestCase):
    """Test cases for Traffic Generator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'traffic_config.yaml')
        
        # Create test configuration
        test_config = {
            'src_ips': ['10.0.1.1', '10.0.1.2'],
            'dst_ips': ['10.0.2.1', '10.0.2.2'],
            'src_ports': list(range(1024, 1034)),
            'dst_ports': [80, 443, 22, 53],
            'patterns': {
                'normal_traffic': {
                    'enabled': True,
                    'rate': 1,
                    'duration': 5
                },
                'http_traffic': {
                    'enabled': True,
                    'rate': 1,
                    'duration': 5
                }
            }
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(test_config, f)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_generator_initialization(self):
        """Test traffic generator initialization"""
        generator = TrafficGenerator(self.config_file)
        
        self.assertIsNotNone(generator.config)
        self.assertIsNotNone(generator.logger)
        self.assertFalse(generator.running)
        self.assertEqual(len(generator.threads), 0)
    
    def test_config_loading(self):
        """Test configuration loading"""
        generator = TrafficGenerator(self.config_file)
        
        self.assertIn('src_ips', generator.config)
        self.assertIn('dst_ips', generator.config)
        self.assertIn('patterns', generator.config)
    
    @patch('scripts.traffic_generator.sendp')
    def test_tcp_packet_generation(self, mock_sendp):
        """Test TCP packet generation"""
        generator = TrafficGenerator(self.config_file)
        
        generator.send_tcp_packet('10.0.1.1', '10.0.2.1', 12345, 80)
        
        mock_sendp.assert_called_once()
        call_args = mock_sendp.call_args[0][0]
        self.assertIsNotNone(call_args)
    
    @patch('scripts.traffic_generator.sendp')
    def test_udp_packet_generation(self, mock_sendp):
        """Test UDP packet generation"""
        generator = TrafficGenerator(self.config_file)
        
        generator.send_udp_packet('10.0.1.1', '10.0.2.1', 12345, 53)
        
        mock_sendp.assert_called_once()
        call_args = mock_sendp.call_args[0][0]
        self.assertIsNotNone(call_args)
    
    @patch('scripts.traffic_generator.sendp')
    def test_icmp_packet_generation(self, mock_sendp):
        """Test ICMP packet generation"""
        generator = TrafficGenerator(self.config_file)
        
        generator.send_icmp_packet('10.0.1.1', '10.0.2.1')
        
        mock_sendp.assert_called_once()
        call_args = mock_sendp.call_args[0][0]
        self.assertIsNotNone(call_args)

class TestWebInterface(unittest.TestCase):
    """Test cases for Web Interface"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'web_config.yaml')
        self.db_file = os.path.join(self.temp_dir, 'test.db')
        
        # Create test configuration
        test_config = {
            'web_interface': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': False
            },
            'performance': {
                'database': {
                    'file': self.db_file
                }
            }
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        # Create test database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                is_suspicious BOOLEAN
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_count INTEGER,
                total_bytes INTEGER,
                is_suspicious BOOLEAN
            )
        ''')
        
        # Insert test data
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, is_suspicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('2024-01-15T10:30:45', '10.0.1.1', '10.0.2.1', 12345, 80, 'TCP', 64, 0))
        
        cursor.execute('''
            INSERT INTO flows (flow_id, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes, is_suspicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('test_flow', '10.0.1.1', '10.0.2.1', 12345, 80, 'TCP', 10, 640, 0))
        
        conn.commit()
        conn.close()
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_web_interface_initialization(self):
        """Test web interface initialization"""
        web_interface = DPIWebInterface(self.config_file)
        
        self.assertIsNotNone(web_interface.config)
        self.assertIsNotNone(web_interface.logger)
        self.assertEqual(web_interface.db_file, self.db_file)
    
    def test_system_stats(self):
        """Test system statistics retrieval"""
        web_interface = DPIWebInterface(self.config_file)
        
        stats = web_interface.get_system_stats()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('timestamp', stats)
        self.assertIn('packet_stats', stats)
        self.assertIn('top_protocols', stats)
        self.assertIn('top_ports', stats)
        self.assertIn('top_ips', stats)
        self.assertIn('recent_flows', stats)

class TestIntegration(unittest.TestCase):
    """Integration tests for the entire system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_system_components_integration(self):
        """Test integration between system components"""
        # This would test the interaction between different components
        # For now, we'll just verify that components can be imported
        from scripts.p4_controller import DPIController
        from scripts.packet_logger import PacketLogger
        from scripts.traffic_generator import TrafficGenerator
        from scripts.web_interface import DPIWebInterface
        
        self.assertTrue(True)  # If we get here, imports work

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestDPIController))
    test_suite.addTest(unittest.makeSuite(TestPacketLogger))
    test_suite.addTest(unittest.makeSuite(TestTrafficGenerator))
    test_suite.addTest(unittest.makeSuite(TestWebInterface))
    test_suite.addTest(unittest.makeSuite(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
