#!/usr/bin/env python3
"""Minimal test to isolate startup issue"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from start_dpi import DPISystem

print("Creating DPISystem...")
dpi = DPISystem()
print(f"Logger: {dpi.logger}")
print(f"Config keys: {list(dpi.config.keys()) if dpi.config else 'NO CONFIG'}")
print(f"Switches in config: {len(dpi.config.get('switches', []))}")

print("\nTesting compile_p4_program...")
result = dpi.compile_p4_program()
print(f"compile_p4_program returned: {result}")

print("\nTesting start_mininet_topology...")
result = dpi.start_mininet_topology()
print(f"start_mininet_topology returned: {result}")

print("\n waiting 5 seconds for switches...")
import time
time.sleep(5)

print("\nTesting start_p4_controller...")
result = dpi.start_p4_controller()
print(f"start_p4_controller returned: {result}")

print("\nDone. Stopping...")
dpi.stop_system()
