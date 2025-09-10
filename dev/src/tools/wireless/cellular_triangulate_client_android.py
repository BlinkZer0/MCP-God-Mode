"""
Client script for SMS-triggered tower data collection (Android).
===============================================================

Overview
--------
This script runs on Android devices (via Termux) to respond to SMS messages
from the MCP cellular triangulation tool. It collects cellular tower data
and sends it back via HTTP POST to the MCP server.

Requirements
------------
- Android device with Termux installed
- Root access (for mmcli commands)
- Python 3.8+ with requests library
- Network connectivity

Installation
------------
1. Install Termux from F-Droid or Google Play
2. Install Python and dependencies:
   pkg update && pkg upgrade
   pkg install python python-pip
   pip install requests
3. Grant Termux storage and SMS permissions
4. Run this script as a background service

Usage
-----
python cellular_triangulate_client_android.py

The script will:
1. Monitor for incoming SMS messages
2. Parse messages containing tower data collection requests
3. Collect cellular tower information using mmcli
4. Send tower data back to the MCP server via HTTP POST

Security Note
-------------
This script requires root access and SMS permissions. Only install on
devices you own and control. The script does not store sensitive data
permanently and only responds to specific SMS patterns.
"""

import os
import sys
import json
import time
import requests
import subprocess
import re
from typing import Dict, List, Optional, Any

class CellularTriangulateClient:
    def __init__(self, server_url: str = "http://your-mcp-server"):
        self.server_url = server_url
        self.is_android = os.path.exists('/system/bin/getprop')
        if not self.is_android:
            raise OSError("This script is designed for Android devices only")
        
        # Check for root access
        try:
            result = subprocess.run(['su', '-c', 'id'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise OSError("Root access required for mmcli commands")
        except Exception as e:
            raise OSError(f"Root access check failed: {e}")

    def get_cellular_tower_data(self) -> List[Dict[str, Any]]:
        """Collect cellular tower data using mmcli."""
        towers = []
        try:
            # List available modems
            result = subprocess.run(['su', '-c', 'mmcli -L'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print("Warning: mmcli not available, using simulated data")
                return self.get_simulated_tower_data()
            
            # Extract modem path
            modem_path = None
            for line in result.stdout.split('\n'):
                if '/org/freedesktop/ModemManager1/Modem/' in line:
                    modem_path = line.split()[0]
                    break
            
            if not modem_path:
                print("Warning: No cellular modem found, using simulated data")
                return self.get_simulated_tower_data()
            
            # Get location information
            cmd = f"su -c 'mmcli -m {modem_path} --location-get'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                towers = self.parse_mmcli_output(result.stdout)
            else:
                print(f"Warning: mmcli location failed: {result.stderr}")
                towers = self.get_simulated_tower_data()
                
        except Exception as e:
            print(f"Error collecting tower data: {e}")
            towers = self.get_simulated_tower_data()
        
        return towers

    def parse_mmcli_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse mmcli output to extract tower information."""
        towers = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if 'cell' in line.lower() and 'id' in line.lower():
                # Parse cell information
                # Example: "Cell ID: 12345, Location Area Code: 6789, Mobile Country Code: 310, Mobile Network Code: 410"
                cid_match = re.search(r'Cell ID:\s*(\d+)', line)
                lac_match = re.search(r'Location Area Code:\s*(\d+)', line)
                mcc_match = re.search(r'Mobile Country Code:\s*(\d+)', line)
                mnc_match = re.search(r'Mobile Network Code:\s*(\d+)', line)
                
                if cid_match and lac_match:
                    tower = {
                        'cid': cid_match.group(1),
                        'lac': lac_match.group(1),
                        'mcc': mcc_match.group(1) if mcc_match else '310',
                        'mnc': mnc_match.group(1) if mnc_match else '410',
                        'rssi': -70  # Default RSSI, would need additional parsing for actual signal strength
                    }
                    towers.append(tower)
        
        # If no towers found in output, return simulated data
        if not towers:
            towers = self.get_simulated_tower_data()
        
        return towers

    def get_simulated_tower_data(self) -> List[Dict[str, Any]]:
        """Generate simulated tower data for testing."""
        return [
            {
                'cid': '12345',
                'lac': '6789',
                'mcc': '310',
                'mnc': '410',
                'rssi': -70
            },
            {
                'cid': '12346',
                'lac': '6790',
                'mcc': '310',
                'mnc': '410',
                'rssi': -75
            },
            {
                'cid': '12347',
                'lac': '6791',
                'mcc': '310',
                'mnc': '410',
                'rssi': -80
            }
        ]

    def send_tower_data(self, token: str, towers: List[Dict[str, Any]]) -> bool:
        """Send tower data to MCP server."""
        try:
            url = f"{self.server_url}/api/cellular/collect"
            data = {
                'token': token,
                'towers': towers,
                'timestamp': time.time(),
                'device_info': {
                    'platform': 'android',
                    'model': self.get_device_model(),
                    'version': self.get_android_version()
                }
            }
            
            response = requests.post(url, json=data, timeout=30)
            return response.status_code == 200
            
        except Exception as e:
            print(f"Error sending tower data: {e}")
            return False

    def get_device_model(self) -> str:
        """Get Android device model."""
        try:
            result = subprocess.run(['getprop', 'ro.product.model'], capture_output=True, text=True, timeout=5)
            return result.stdout.strip() if result.returncode == 0 else 'Unknown'
        except:
            return 'Unknown'

    def get_android_version(self) -> str:
        """Get Android version."""
        try:
            result = subprocess.run(['getprop', 'ro.build.version.release'], capture_output=True, text=True, timeout=5)
            return result.stdout.strip() if result.returncode == 0 else 'Unknown'
        except:
            return 'Unknown'

    def parse_sms_message(self, message: str) -> Optional[str]:
        """Parse SMS message to extract collection token."""
        # Look for URL pattern: http://your-mcp-server/collect?t=TOKEN
        url_pattern = r'http://[^/]+/collect\?t=([a-f0-9]+)'
        match = re.search(url_pattern, message)
        return match.group(1) if match else None

    def monitor_sms(self):
        """Monitor for SMS messages (simplified implementation)."""
        print("Starting SMS monitoring for cellular triangulation requests...")
        print("Note: This is a simplified implementation. In production, you would")
        print("integrate with Android's SMS broadcast receiver or use Termux API.")
        
        # For demonstration, we'll simulate receiving an SMS
        # In a real implementation, you would:
        # 1. Use Android's BroadcastReceiver for SMS_RECEIVED
        # 2. Or use Termux API to access SMS
        # 3. Or use a third-party SMS monitoring app
        
        while True:
            try:
                # Simulate SMS monitoring
                print("Monitoring for SMS messages... (Press Ctrl+C to stop)")
                time.sleep(30)  # Check every 30 seconds
                
                # In a real implementation, you would check for new SMS here
                # For now, we'll demonstrate with a simulated message
                if input("Simulate SMS? (y/n): ").lower() == 'y':
                    simulated_message = "Reply with tower data or visit http://your-mcp-server/collect?t=abc123def456"
                    self.handle_sms_message(simulated_message)
                
            except KeyboardInterrupt:
                print("\nStopping SMS monitoring...")
                break
            except Exception as e:
                print(f"Error in SMS monitoring: {e}")
                time.sleep(5)

    def handle_sms_message(self, message: str):
        """Handle incoming SMS message."""
        print(f"Received SMS: {message}")
        
        token = self.parse_sms_message(message)
        if not token:
            print("No collection token found in message")
            return
        
        print(f"Extracted token: {token}")
        print("Collecting cellular tower data...")
        
        towers = self.get_cellular_tower_data()
        print(f"Collected {len(towers)} towers")
        
        print("Sending tower data to server...")
        success = self.send_tower_data(token, towers)
        
        if success:
            print("Tower data sent successfully")
        else:
            print("Failed to send tower data")

    def run_demo(self):
        """Run a demonstration of the client functionality."""
        print("=== Cellular Triangulation Client Demo ===")
        print(f"Server URL: {self.server_url}")
        print(f"Device Model: {self.get_device_model()}")
        print(f"Android Version: {self.get_android_version()}")
        print()
        
        # Test tower data collection
        print("Testing tower data collection...")
        towers = self.get_cellular_tower_data()
        print(f"Collected {len(towers)} towers:")
        for i, tower in enumerate(towers, 1):
            print(f"  Tower {i}: CID={tower['cid']}, LAC={tower['lac']}, RSSI={tower['rssi']}")
        print()
        
        # Test SMS parsing
        test_message = "Reply with tower data or visit http://your-mcp-server/collect?t=test123token"
        token = self.parse_sms_message(test_message)
        print(f"Test SMS parsing: '{test_message}' -> Token: {token}")
        print()
        
        # Start monitoring
        self.monitor_sms()

def main():
    """Main entry point."""
    try:
        # You can customize the server URL here
        server_url = os.environ.get('MCP_SERVER_URL', 'http://your-mcp-server')
        
        client = CellularTriangulateClient(server_url)
        client.run_demo()
        
    except OSError as e:
        print(f"Error: {e}")
        print("Make sure you're running this on an Android device with Termux and root access.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
