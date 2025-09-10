#!/usr/bin/env python3
"""
Comprehensive Enhanced Drone Tools Test Suite - MCP God Mode v1.8
Tests both Python and TypeScript implementations for cross-platform compatibility
"""

import os
import sys
import json
import subprocess
import time
import platform
from datetime import datetime
from typing import Dict, List, Any, Optional

class ComprehensiveDroneToolsTester:
    """Comprehensive test suite for enhanced drone tools"""
    
    def __init__(self):
        self.test_results = []
        self.platform = self.detect_platform()
        self.is_mobile = self.platform in ['android', 'ios']
        self.node_available = self.check_node_availability()
        self.python_available = self.check_python_availability()
        
    def detect_platform(self) -> str:
        """Detect current platform"""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        else:
            # Check for mobile platforms
            if os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA"):
                return "android"
            elif os.environ.get("IOS_SIMULATOR") or os.environ.get("IOS_PLATFORM"):
                return "ios"
            return "unknown"
    
    def check_node_availability(self) -> bool:
        """Check if Node.js is available"""
        try:
            result = subprocess.run(['node', '--version'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def check_python_availability(self) -> bool:
        """Check if Python is available"""
        try:
            result = subprocess.run([sys.executable, '--version'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test result"""
        result = {
            'test_name': test_name,
            'success': success,
            'details': details,
            'platform': self.platform,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name} - {details}")
    
    def test_python_enhanced_drone_defense(self):
        """Test Python enhanced drone defense tool"""
        if not self.python_available:
            self.log_test(
                "Python Enhanced Drone Defense",
                False,
                "Python not available"
            )
            return
            
        try:
            # Test basic functionality
            cmd = [
                sys.executable, "src/tools/drone_defense_enhanced.py",
                "--action", "scan_surroundings",
                "--threat_type", "ddos",
                "--target", "192.168.1.0/24",
                "--auto_confirm"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse JSON output
                output = json.loads(result.stdout)
                self.log_test(
                    "Python Enhanced Drone Defense - Basic",
                    True,
                    f"Operation ID: {output.get('operation_id', 'N/A')}"
                )
                
                # Test natural language interface
                cmd_nlp = [
                    sys.executable, "src/tools/drone_defense_enhanced.py",
                    "--natural_language", "scan for threats on the network",
                    "--target", "192.168.1.0/24",
                    "--auto_confirm"
                ]
                
                result_nlp = subprocess.run(cmd_nlp, capture_output=True, text=True, timeout=30)
                
                if result_nlp.returncode == 0:
                    self.log_test(
                        "Python Enhanced Drone Defense - Natural Language",
                        True,
                        "Natural language parsing successful"
                    )
                else:
                    self.log_test(
                        "Python Enhanced Drone Defense - Natural Language",
                        False,
                        f"Error: {result_nlp.stderr}"
                    )
            else:
                self.log_test(
                    "Python Enhanced Drone Defense - Basic",
                    False,
                    f"Error: {result.stderr}"
                )
                
        except Exception as e:
            self.log_test(
                "Python Enhanced Drone Defense - Basic",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_typescript_compilation(self):
        """Test TypeScript compilation"""
        if not self.node_available:
            self.log_test(
                "TypeScript Compilation",
                False,
                "Node.js not available"
            )
            return
            
        try:
            # Test TypeScript compilation
            result = subprocess.run(['npm', 'run', 'build'], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self.log_test(
                    "TypeScript Compilation",
                    True,
                    "All TypeScript files compiled successfully"
                )
                
                # Check if enhanced drone tool files exist
                enhanced_files = [
                    "dist/tools/droneDefenseEnhanced.js",
                    "dist/tools/droneOffenseEnhanced.js",
                    "dist/tools/droneNaturalLanguageInterface.js",
                    "dist/tools/droneMobileOptimized.js"
                ]
                
                files_exist = all(os.path.exists(f) for f in enhanced_files)
                
                self.log_test(
                    "Enhanced Drone Tool Files - Existence",
                    files_exist,
                    f"Found {sum(os.path.exists(f) for f in enhanced_files)}/{len(enhanced_files)} files"
                )
                
            else:
                self.log_test(
                    "TypeScript Compilation",
                    False,
                    f"Compilation failed: {result.stderr}"
                )
                
        except Exception as e:
            self.log_test(
                "TypeScript Compilation",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_typescript_enhanced_drone_tools(self):
        """Test TypeScript enhanced drone tools"""
        if not self.node_available:
            self.log_test(
                "TypeScript Enhanced Drone Tools",
                False,
                "Node.js not available"
            )
            return
            
        try:
            # Test TypeScript enhanced drone tools test script
            result = subprocess.run(['node', 'test_enhanced_drone_tools_ts.mjs'], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self.log_test(
                    "TypeScript Enhanced Drone Tools - Test Suite",
                    True,
                    "Test suite executed successfully"
                )
                
                # Parse test results from output
                if "Success Rate:" in result.stdout:
                    success_rate_line = [line for line in result.stdout.split('\n') if 'Success Rate:' in line][0]
                    success_rate = success_rate_line.split(':')[1].strip()
                    
                    self.log_test(
                        "TypeScript Enhanced Drone Tools - Success Rate",
                        True,
                        f"Success rate: {success_rate}"
                    )
                else:
                    self.log_test(
                        "TypeScript Enhanced Drone Tools - Success Rate",
                        False,
                        "Could not parse success rate"
                    )
                    
            else:
                self.log_test(
                    "TypeScript Enhanced Drone Tools - Test Suite",
                    False,
                    f"Test suite failed: {result.stderr}"
                )
                
        except Exception as e:
            self.log_test(
                "TypeScript Enhanced Drone Tools - Test Suite",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_cross_platform_capabilities(self):
        """Test cross-platform capabilities"""
        try:
            # Test platform detection
            from src.tools.drone_defense_enhanced import PlatformDetector
            
            detected_platform = PlatformDetector.detect_platform()
            is_mobile = PlatformDetector.is_mobile()
            capabilities = PlatformDetector.get_mobile_capabilities()
            
            self.log_test(
                "Cross-Platform Detection - Python",
                True,
                f"Platform: {detected_platform}, Mobile: {is_mobile}, Capabilities: {len(capabilities)}"
            )
            
            # Test mobile optimizations if on mobile
            if is_mobile:
                self.log_test(
                    "Mobile Capabilities Detection - Python",
                    len(capabilities) > 0,
                    f"Found {len(capabilities)} mobile capabilities"
                )
            else:
                self.log_test(
                    "Desktop Platform Detection - Python",
                    True,
                    f"Running on desktop platform: {detected_platform}"
                )
                
        except Exception as e:
            self.log_test(
                "Cross-Platform Detection - Python",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_natural_language_processing(self):
        """Test natural language processing capabilities"""
        try:
            from src.tools.drone_defense_enhanced import NaturalLanguageProcessor
            
            # Test various natural language commands
            test_commands = [
                "scan for threats",
                "deploy protection against ddos attacks",
                "evade the intrusion attempt",
                "find suspicious activity on the network",
                "shield the system from malware"
            ]
            
            successful_parses = 0
            for command in test_commands:
                try:
                    action, threat_type, confidence = NaturalLanguageProcessor.parse_command(command)
                    if confidence > 0.5:
                        successful_parses += 1
                except:
                    pass
            
            self.log_test(
                "Natural Language Processing - Python",
                successful_parses >= len(test_commands) * 0.8,
                f"Successfully parsed {successful_parses}/{len(test_commands)} commands"
            )
                
        except Exception as e:
            self.log_test(
                "Natural Language Processing - Python",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_mobile_optimizations(self):
        """Test mobile-specific optimizations"""
        if not self.is_mobile:
            self.log_test(
                "Mobile Optimizations",
                True,
                "Skipped - not running on mobile platform"
            )
            return
            
        try:
            # Test mobile command generation
            from src.tools.drone_defense_enhanced import CrossPlatformDroneDefenseManager
            
            manager = CrossPlatformDroneDefenseManager()
            
            # Test mobile command generation
            mobile_cmd = manager.get_mobile_command("scan_surroundings", "192.168.1.0/24")
            
            self.log_test(
                "Mobile Command Generation - Python",
                "battery-optimized" in mobile_cmd,
                f"Generated mobile command: {mobile_cmd[:50]}..."
            )
            
            # Test mobile capabilities
            capabilities = manager.mobile_capabilities
            
            self.log_test(
                "Mobile Capabilities Detection - Python",
                len(capabilities) > 0,
                f"Detected {len(capabilities)} mobile capabilities"
            )
            
        except Exception as e:
            self.log_test(
                "Mobile Optimizations - Python",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_audit_logging(self):
        """Test audit logging functionality"""
        try:
            from src.tools.drone_defense_enhanced import CrossPlatformDroneDefenseManager
            
            # Set environment for audit logging
            os.environ['MCPGM_AUDIT_ENABLED'] = 'true'
            
            manager = CrossPlatformDroneDefenseManager()
            
            # Execute a simple operation
            report = manager.execute_action(
                "scan_surroundings",
                "ddos",
                "192.168.1.0/24",
                auto_confirm=True
            )
            
            self.log_test(
                "Audit Logging - Python",
                len(report.audit_log) > 0,
                f"Generated {len(report.audit_log)} audit log entries"
            )
            
        except Exception as e:
            self.log_test(
                "Audit Logging - Python",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_natural_language_response_generation(self):
        """Test natural language response generation"""
        try:
            from src.tools.drone_defense_enhanced import CrossPlatformDroneDefenseManager, NaturalLanguageProcessor
            
            manager = CrossPlatformDroneDefenseManager()
            
            # Execute operation
            report = manager.execute_action(
                "scan_surroundings",
                "ddos",
                "192.168.1.0/24",
                auto_confirm=True
            )
            
            # Test response generation
            response = NaturalLanguageProcessor.generate_response(report)
            
            self.log_test(
                "Natural Language Response Generation - Python",
                len(response) > 100 and "🛸" in response,
                f"Generated response length: {len(response)} characters"
            )
            
        except Exception as e:
            self.log_test(
                "Natural Language Response Generation - Python",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_environment_configuration(self):
        """Test environment configuration"""
        try:
            # Test environment variables
            required_env_vars = [
                'MCPGM_DRONE_ENABLED',
                'MCPGM_DRONE_SIM_ONLY',
                'MCPGM_REQUIRE_CONFIRMATION',
                'MCPGM_AUDIT_ENABLED'
            ]
            
            env_vars_found = 0
            for env_var in required_env_vars:
                if os.environ.get(env_var):
                    env_vars_found += 1
            
            self.log_test(
                "Environment Configuration",
                env_vars_found > 0,
                f"Found {env_vars_found}/{len(required_env_vars)} environment variables"
            )
            
        except Exception as e:
            self.log_test(
                "Environment Configuration",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_file_structure(self):
        """Test file structure and organization"""
        try:
            # Check for required files
            required_files = [
                "src/tools/drone_defense_enhanced.py",
                "src/tools/droneDefenseEnhanced.ts",
                "src/tools/droneOffenseEnhanced.ts",
                "src/tools/droneNaturalLanguageInterface.ts",
                "src/tools/droneMobileOptimized.ts",
                "test_enhanced_drone_tools.py",
                "test_enhanced_drone_tools_ts.js",
                "test_enhanced_drone_tools_comprehensive.py"
            ]
            
            files_exist = 0
            for file_path in required_files:
                if os.path.exists(file_path):
                    files_exist += 1
            
            self.log_test(
                "File Structure - Required Files",
                files_exist >= len(required_files) * 0.8,
                f"Found {files_exist}/{len(required_files)} required files"
            )
            
        except Exception as e:
            self.log_test(
                "File Structure - Required Files",
                False,
                f"Exception: {str(e)}"
            )
    
    def run_all_tests(self):
        """Run all tests"""
        print("🧪 Comprehensive Enhanced Drone Tools Test Suite - MCP God Mode v1.8")
        print("=" * 80)
        print(f"Platform: {self.platform}")
        print(f"Mobile: {self.is_mobile}")
        print(f"Node.js Available: {self.node_available}")
        print(f"Python Available: {self.python_available}")
        print("=" * 80)
        
        # Run all tests
        self.test_python_enhanced_drone_defense()
        self.test_typescript_compilation()
        self.test_typescript_enhanced_drone_tools()
        self.test_cross_platform_capabilities()
        self.test_natural_language_processing()
        self.test_mobile_optimizations()
        self.test_audit_logging()
        self.test_natural_language_response_generation()
        self.test_environment_configuration()
        self.test_file_structure()
        
        # Generate summary
        self.generate_summary()
    
    def generate_summary(self):
        """Generate test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  • {result['test_name']}: {result['details']}")
        
        # Save results to file
        results_file = f"test_results_comprehensive_enhanced_drone_{self.platform}_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump({
                'summary': {
                    'total_tests': total_tests,
                    'passed_tests': passed_tests,
                    'failed_tests': failed_tests,
                    'success_rate': (passed_tests/total_tests)*100,
                    'platform': self.platform,
                    'is_mobile': self.is_mobile,
                    'node_available': self.node_available,
                    'python_available': self.python_available,
                    'timestamp': datetime.now().isoformat()
                },
                'test_results': self.test_results
            }, f, indent=2)
        
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        return passed_tests == total_tests

def main():
    """Main function"""
    tester = ComprehensiveDroneToolsTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
