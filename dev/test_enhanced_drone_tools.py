#!/usr/bin/env python3
"""
Enhanced Drone Tools Test Suite - MCP God Mode v1.8
Comprehensive testing for cross-platform drone tools with natural language interface
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any

class EnhancedDroneToolsTester:
    """Test suite for enhanced drone tools"""
    
    def __init__(self):
        self.test_results = []
        self.platform = self.detect_platform()
        self.is_mobile = self.platform in ['android', 'ios']
        
    def detect_platform(self) -> str:
        """Detect current platform"""
        import platform
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
    
    def test_enhanced_drone_defense_python(self):
        """Test enhanced Python drone defense tool"""
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
                    "Enhanced Python Drone Defense - Basic",
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
                        "Enhanced Python Drone Defense - Natural Language",
                        True,
                        "Natural language parsing successful"
                    )
                else:
                    self.log_test(
                        "Enhanced Python Drone Defense - Natural Language",
                        False,
                        f"Error: {result_nlp.stderr}"
                    )
            else:
                self.log_test(
                    "Enhanced Python Drone Defense - Basic",
                    False,
                    f"Error: {result.stderr}"
                )
                
        except Exception as e:
            self.log_test(
                "Enhanced Python Drone Defense - Basic",
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
                "Cross-Platform Detection",
                True,
                f"Platform: {detected_platform}, Mobile: {is_mobile}, Capabilities: {len(capabilities)}"
            )
            
            # Test mobile optimizations if on mobile
            if is_mobile:
                self.log_test(
                    "Mobile Capabilities Detection",
                    len(capabilities) > 0,
                    f"Found {len(capabilities)} mobile capabilities"
                )
            else:
                self.log_test(
                    "Desktop Platform Detection",
                    True,
                    f"Running on desktop platform: {detected_platform}"
                )
                
        except Exception as e:
            self.log_test(
                "Cross-Platform Detection",
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
            
            for command in test_commands:
                action, threat_type, confidence = NaturalLanguageProcessor.parse_command(command)
                
                self.log_test(
                    f"Natural Language Processing - '{command[:20]}...'",
                    confidence > 0.5,
                    f"Action: {action}, Threat: {threat_type}, Confidence: {confidence:.2f}"
                )
                
        except Exception as e:
            self.log_test(
                "Natural Language Processing",
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
                "Mobile Command Generation",
                "battery-optimized" in mobile_cmd,
                f"Generated mobile command: {mobile_cmd[:50]}..."
            )
            
            # Test mobile capabilities
            capabilities = manager.mobile_capabilities
            
            self.log_test(
                "Mobile Capabilities Detection",
                len(capabilities) > 0,
                f"Detected {len(capabilities)} mobile capabilities"
            )
            
        except Exception as e:
            self.log_test(
                "Mobile Optimizations",
                False,
                f"Exception: {str(e)}"
            )
    
    def test_platform_specific_commands(self):
        """Test platform-specific command generation"""
        try:
            from src.tools.drone_defense_enhanced import CrossPlatformDroneDefenseManager
            
            manager = CrossPlatformDroneDefenseManager()
            
            # Test command generation for different platforms
            desktop_cmd = manager.get_desktop_command("scan_surroundings", "192.168.1.0/24")
            mobile_cmd = manager.get_mobile_command("scan_surroundings", "192.168.1.0/24")
            
            self.log_test(
                "Platform-Specific Commands - Desktop",
                "full-capabilities" in desktop_cmd,
                f"Desktop command: {desktop_cmd[:50]}..."
            )
            
            self.log_test(
                "Platform-Specific Commands - Mobile",
                "battery-optimized" in mobile_cmd,
                f"Mobile command: {mobile_cmd[:50]}..."
            )
            
        except Exception as e:
            self.log_test(
                "Platform-Specific Commands",
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
                "Audit Logging",
                len(report.audit_log) > 0,
                f"Generated {len(report.audit_log)} audit log entries"
            )
            
        except Exception as e:
            self.log_test(
                "Audit Logging",
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
                "Natural Language Response Generation",
                len(response) > 100 and "🛸" in response,
                f"Generated response length: {len(response)} characters"
            )
            
        except Exception as e:
            self.log_test(
                "Natural Language Response Generation",
                False,
                f"Exception: {str(e)}"
            )
    
    def run_all_tests(self):
        """Run all tests"""
        print("🧪 Enhanced Drone Tools Test Suite - MCP God Mode v1.8")
        print("=" * 60)
        print(f"Platform: {self.platform}")
        print(f"Mobile: {self.is_mobile}")
        print("=" * 60)
        
        # Run all tests
        self.test_enhanced_drone_defense_python()
        self.test_cross_platform_capabilities()
        self.test_natural_language_processing()
        self.test_mobile_optimizations()
        self.test_platform_specific_commands()
        self.test_audit_logging()
        self.test_natural_language_response_generation()
        
        # Generate summary
        self.generate_summary()
    
    def generate_summary(self):
        """Generate test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
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
        results_file = f"test_results_enhanced_drone_{self.platform}_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump({
                'summary': {
                    'total_tests': total_tests,
                    'passed_tests': passed_tests,
                    'failed_tests': failed_tests,
                    'success_rate': (passed_tests/total_tests)*100,
                    'platform': self.platform,
                    'timestamp': datetime.now().isoformat()
                },
                'test_results': self.test_results
            }, f, indent=2)
        
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        return passed_tests == total_tests

def main():
    """Main function"""
    tester = EnhancedDroneToolsTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
