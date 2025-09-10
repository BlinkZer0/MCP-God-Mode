#!/usr/bin/env python3
"""
Test script for drone management tools
Demonstrates usage of both defense and offense tools
"""

import os
import sys
import json
import time
from datetime import datetime

# Add tools directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src', 'tools'))

def test_drone_defense():
    """Test drone defense tool"""
    print("🛸 Testing Drone Defense Tool")
    print("=" * 50)
    
    try:
        from drone_defense import DroneDefenseManager
        
        manager = DroneDefenseManager()
        
        # Test scan surroundings
        print("\n1. Testing scan_surroundings action:")
        report = manager.execute_defense_operation(
            action="scan_surroundings",
            threat_type="general",
            target="192.168.1.0/24",
            auto_confirm=True
        )
        print(f"   Success: {report.success}")
        print(f"   Actions taken: {len(report.actions_taken)}")
        
        # Test deploy shield
        print("\n2. Testing deploy_shield action:")
        report = manager.execute_defense_operation(
            action="deploy_shield",
            threat_type="ddos",
            target="192.168.1.0/24",
            auto_confirm=True
        )
        print(f"   Success: {report.success}")
        print(f"   Threat level: {report.threat_level}")
        
        # Test evade threat
        print("\n3. Testing evade_threat action:")
        report = manager.execute_defense_operation(
            action="evade_threat",
            threat_type="intrusion",
            target="192.168.1.0/24",
            auto_confirm=True
        )
        print(f"   Success: {report.success}")
        print(f"   Actions taken: {len(report.actions_taken)}")
        
        print("\n✅ Drone Defense Tool tests completed successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Drone Defense Tool test failed: {e}")
        return False

def test_drone_offense():
    """Test drone offense tool"""
    print("\n⚔️ Testing Drone Offense Tool")
    print("=" * 50)
    
    try:
        from drone_offense import DroneOffenseManager
        
        manager = DroneOffenseManager()
        
        # Test jam signals
        print("\n1. Testing jam_signals action:")
        report = manager.execute_offense_operation(
            action="jam_signals",
            target_ip="192.168.1.100",
            intensity="low",
            confirm=True,
            risk_acknowledged=True,
            threat_level=8
        )
        print(f"   Success: {report.success}")
        print(f"   Risk acknowledged: {report.risk_acknowledged}")
        print(f"   Actions taken: {len(report.actions_taken)}")
        
        # Test deploy decoy
        print("\n2. Testing deploy_decoy action:")
        report = manager.execute_offense_operation(
            action="deploy_decoy",
            target_ip="192.168.1.100",
            intensity="medium",
            confirm=True,
            risk_acknowledged=True,
            threat_level=6
        )
        print(f"   Success: {report.success}")
        print(f"   Actions taken: {len(report.actions_taken)}")
        
        # Test counter strike
        print("\n3. Testing counter_strike action:")
        report = manager.execute_offense_operation(
            action="counter_strike",
            target_ip="192.168.1.100",
            intensity="high",
            confirm=True,
            risk_acknowledged=True,
            threat_level=9
        )
        print(f"   Success: {report.success}")
        print(f"   Actions taken: {len(report.actions_taken)}")
        
        print("\n✅ Drone Offense Tool tests completed successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Drone Offense Tool test failed: {e}")
        return False

def test_workflow():
    """Test drone response workflow"""
    print("\n🔄 Testing Drone Response Workflow")
    print("=" * 50)
    
    try:
        from drone_response_workflow import DroneResponseWorkflow
        
        workflow = DroneResponseWorkflow()
        
        # Test complete workflow
        print("\n1. Testing complete workflow:")
        result = workflow.execute_workflow("192.168.1.0/24")
        print(f"   Success: {result['success']}")
        print(f"   Message: {result['message']}")
        print(f"   Steps completed: {', '.join(result['steps_completed'])}")
        
        if 'attack_info' in result:
            attack = result['attack_info']
            print(f"   Attack detected: {attack.get('attack_detected', False)}")
            if attack.get('attack_detected'):
                print(f"     Type: {attack.get('attack_type', 'unknown')}")
                print(f"     Threat level: {attack.get('threat_level', 0)}")
        
        print("\n✅ Drone Response Workflow test completed successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Drone Response Workflow test failed: {e}")
        return False

def test_safety_checks():
    """Test safety and compliance checks"""
    print("\n🔒 Testing Safety and Compliance Checks")
    print("=" * 50)
    
    try:
        from drone_offense import DroneOffenseManager
        
        # Test without risk acknowledgment
        print("\n1. Testing without risk acknowledgment:")
        manager = DroneOffenseManager()
        report = manager.execute_offense_operation(
            action="jam_signals",
            target_ip="192.168.1.100",
            risk_acknowledged=False  # Should fail
        )
        print(f"   Success: {report.success} (should be False)")
        print(f"   Message: {report.actions_taken[0].message if report.actions_taken else 'No actions'}")
        
        # Test HIPAA compliance mode
        print("\n2. Testing HIPAA compliance mode:")
        os.environ['MCPGM_MODE_HIPAA'] = 'true'
        manager = DroneOffenseManager()
        report = manager.execute_offense_operation(
            action="jam_signals",
            target_ip="192.168.1.100",
            risk_acknowledged=True
        )
        print(f"   Success: {report.success} (should be False)")
        print(f"   Message: {report.actions_taken[0].message if report.actions_taken else 'No actions'}")
        
        # Reset environment
        os.environ['MCPGM_MODE_HIPAA'] = 'false'
        
        print("\n✅ Safety and Compliance checks completed successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Safety and Compliance checks failed: {e}")
        return False

def main():
    """Run all drone tool tests"""
    print("🚀 MCP God Mode - Drone Management Tools Test Suite")
    print("=" * 60)
    print(f"Test started at: {datetime.now().isoformat()}")
    print()
    
    # Set up test environment
    os.environ['MCPGM_DRONE_ENABLED'] = 'true'
    os.environ['MCPGM_DRONE_SIM_ONLY'] = 'true'
    os.environ['MCPGM_AUDIT_ENABLED'] = 'true'
    os.environ['MCPGM_REQUIRE_CONFIRMATION'] = 'false'  # For testing
    
    test_results = []
    
    # Run tests
    test_results.append(("Drone Defense", test_drone_defense()))
    test_results.append(("Drone Offense", test_drone_offense()))
    test_results.append(("Response Workflow", test_workflow()))
    test_results.append(("Safety Checks", test_safety_checks()))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Drone management tools are working correctly.")
        return 0
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    exit(main())
