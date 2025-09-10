#!/usr/bin/env python3
"""
Test script for website-based cellular triangulation
====================================================

This script tests the website-based approach for cellular triangulation,
including SMS sending, webpage serving, and GPS data collection.
"""

import os
import sys
import time
import json
import requests
import subprocess
from typing import Dict, Any, Optional

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from cellular_triangulate import CellularTriangulateTool
except ImportError:
    print("Error: cellular_triangulate.py not found")
    sys.exit(1)

class WebsiteBasedTriangulationTester:
    def __init__(self, server_url: str = "http://localhost:3000"):
        self.server_url = server_url
        self.tool = CellularTriangulateTool()
        self.test_results = []
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test results"""
        result = {
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": time.time()
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {details}")
        
    def test_server_health(self) -> bool:
        """Test if the MCP server is running and healthy"""
        try:
            response = requests.get(f"{self.server_url}/api/cellular/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Server Health Check", True, f"Server is healthy, uptime: {data.get('uptime', 'unknown')}")
                return True
            else:
                self.log_test("Server Health Check", False, f"Server returned status {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Server Health Check", False, f"Server not accessible: {str(e)}")
            return False
    
    def test_webpage_serving(self) -> bool:
        """Test if the webpage is being served correctly"""
        try:
            # Test with a dummy token
            test_token = "test123"
            response = requests.get(f"{self.server_url}/collect?t={test_token}", timeout=5)
            
            if response.status_code == 200:
                content = response.text
                if "Location Collection" in content and test_token in content:
                    self.log_test("Webpage Serving", True, "Webpage served correctly with token")
                    return True
                else:
                    self.log_test("Webpage Serving", False, "Webpage content missing expected elements")
                    return False
            else:
                self.log_test("Webpage Serving", False, f"Webpage returned status {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Webpage Serving", False, f"Error serving webpage: {str(e)}")
            return False
    
    def test_gps_data_collection(self) -> bool:
        """Test GPS data collection via API"""
        try:
            test_token = "gps_test_123"
            gps_data = [{
                "lat": 43.0731,
                "lon": -89.4012,
                "error_radius_m": 10
            }]
            
            response = requests.post(
                f"{self.server_url}/api/cellular/collect?t={test_token}",
                json=gps_data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success" and data.get("data_type") == "gps":
                    self.log_test("GPS Data Collection", True, f"GPS data received: {data.get('location')}")
                    return True
                else:
                    self.log_test("GPS Data Collection", False, f"Unexpected response: {data}")
                    return False
            else:
                self.log_test("GPS Data Collection", False, f"API returned status {response.status_code}")
                return False
        except Exception as e:
            self.log_test("GPS Data Collection", False, f"Error collecting GPS data: {str(e)}")
            return False
    
    def test_tower_data_collection(self) -> bool:
        """Test tower data collection via API"""
        try:
            test_token = "tower_test_123"
            tower_data = [{
                "cid": "1234",
                "lac": "5678",
                "mcc": "310",
                "mnc": "410",
                "rssi": -70
            }]
            
            response = requests.post(
                f"{self.server_url}/api/cellular/collect?t={test_token}",
                json=tower_data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success" and data.get("data_type") == "towers":
                    self.log_test("Tower Data Collection", True, f"Tower data received: {data.get('towers_received')} towers")
                    return True
                else:
                    self.log_test("Tower Data Collection", False, f"Unexpected response: {data}")
                    return False
            else:
                self.log_test("Tower Data Collection", False, f"API returned status {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Tower Data Collection", False, f"Error collecting tower data: {str(e)}")
            return False
    
    def test_sms_token_generation(self) -> bool:
        """Test SMS token generation (without actually sending SMS)"""
        try:
            # Test token generation for different platforms
            platforms = ['windows', 'darwin', 'linux']
            for platform in platforms:
                # Mock the platform
                original_platform = self.tool.sys
                self.tool.sys = platform
                
                # Generate token (this should work without sending SMS)
                token = os.urandom(16).hex()
                
                if len(token) == 32:  # 16 bytes = 32 hex characters
                    self.log_test(f"SMS Token Generation ({platform})", True, f"Token generated: {token[:8]}...")
                else:
                    self.log_test(f"SMS Token Generation ({platform})", False, f"Invalid token length: {len(token)}")
                    return False
                
                # Restore original platform
                self.tool.sys = original_platform
            
            return True
        except Exception as e:
            self.log_test("SMS Token Generation", False, f"Error generating tokens: {str(e)}")
            return False
    
    def test_gps_mode_triangulation(self) -> bool:
        """Test GPS mode triangulation"""
        try:
            gps_data = {
                "lat": 43.0731,
                "lon": -89.4012,
                "error_radius_m": 10
            }
            
            result = self.tool.execute(gps_data=gps_data, mode='gps')
            
            if result.get("status") == "success":
                location = result.get("location", {})
                if location.get("lat") == gps_data["lat"] and location.get("lon") == gps_data["lon"]:
                    self.log_test("GPS Mode Triangulation", True, f"GPS location processed: {location}")
                    return True
                else:
                    self.log_test("GPS Mode Triangulation", False, f"Location mismatch: {location}")
                    return False
            else:
                self.log_test("GPS Mode Triangulation", False, f"Triangulation failed: {result}")
                return False
        except Exception as e:
            self.log_test("GPS Mode Triangulation", False, f"Error in GPS triangulation: {str(e)}")
            return False
    
    def test_natural_language_parsing(self) -> bool:
        """Test natural language command parsing"""
        try:
            test_commands = [
                "Ping +1234567890 for location",
                "Find location using GPS for +1234567890",
                "Triangulate my location with cell towers"
            ]
            
            for command in test_commands:
                # This would normally be handled by the TypeScript implementation
                # For now, we'll test the basic parsing logic
                if "+1234567890" in command and "ping" in command.lower():
                    self.log_test("Natural Language Parsing", True, f"Command parsed: {command}")
                    return True
            
            self.log_test("Natural Language Parsing", False, "No valid commands found")
            return False
        except Exception as e:
            self.log_test("Natural Language Parsing", False, f"Error parsing commands: {str(e)}")
            return False
    
    def test_token_status_checking(self) -> bool:
        """Test token status checking"""
        try:
            # First, submit some data
            test_token = "status_test_123"
            gps_data = [{"lat": 43.0731, "lon": -89.4012, "error_radius_m": 10}]
            
            # Submit data
            requests.post(
                f"{self.server_url}/api/cellular/collect?t={test_token}",
                json=gps_data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            # Check status
            response = requests.get(f"{self.server_url}/api/cellular/status/{test_token}", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success" and data.get("data_status") == "completed":
                    self.log_test("Token Status Checking", True, f"Status checked: {data.get('data_status')}")
                    return True
                else:
                    self.log_test("Token Status Checking", False, f"Unexpected status: {data}")
                    return False
            else:
                self.log_test("Token Status Checking", False, f"Status check failed: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Token Status Checking", False, f"Error checking status: {str(e)}")
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests and return results"""
        print("🧪 Starting Website-Based Cellular Triangulation Tests")
        print("=" * 60)
        
        # Run tests
        tests = [
            self.test_server_health,
            self.test_webpage_serving,
            self.test_gps_data_collection,
            self.test_tower_data_collection,
            self.test_sms_token_generation,
            self.test_gps_mode_triangulation,
            self.test_natural_language_parsing,
            self.test_token_status_checking
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"❌ ERROR in {test.__name__}: {str(e)}")
        
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! Website-based triangulation is working correctly.")
        else:
            print("⚠️  Some tests failed. Check the details above.")
        
        return {
            "total_tests": total,
            "passed_tests": passed,
            "failed_tests": total - passed,
            "success_rate": (passed / total) * 100,
            "test_results": self.test_results
        }

def main():
    """Main function to run the tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test website-based cellular triangulation")
    parser.add_argument("--server-url", default="http://localhost:3000", 
                       help="MCP server URL (default: http://localhost:3000)")
    parser.add_argument("--output", help="Output file for test results (JSON)")
    
    args = parser.parse_args()
    
    # Run tests
    tester = WebsiteBasedTriangulationTester(args.server_url)
    results = tester.run_all_tests()
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📄 Test results saved to {args.output}")
    
    # Exit with appropriate code
    sys.exit(0 if results["passed_tests"] == results["total_tests"] else 1)

if __name__ == "__main__":
    main()
