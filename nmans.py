#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import json
import datetime
from typing import List, Dict




class NmapAdvancedScanner:
    def __init__(self):
        self.targets = []
        self.scan_history = []
        self.port_scan_techniques = {
            "1": {
                "name": "Stealth SYN Scan",
                "cmd": "-sS",
                "description": "Standard stealth scan"
            },
            "2": {
                "name": "TCP ACK Scan",
                "cmd": "-sA",
                "description": "Useful for firewall rule mapping"
            },
            "3": {
                "name": "Window Scan",
                "cmd": "-sW",
                "description": "Similar to ACK scan"
            },
            "4": {
                "name": "Maimon Scan",
                "cmd": "-sM",
                "description": "FIN/ACK probe"
            },
            "5": {
                "name": "FIN Scan",
                "cmd": "-sF",
                "description": "Stealthy scan using FIN flag"
            },
            "6": {
                "name": "NULL Scan",
                "cmd": "-sN",
                "description": "Very stealthy TCP scan"
            },
            "7": {
                "name": "XMAS Scan",
                "cmd": "-sX",
                "description": "Sets FIN, PSH, URG flags"
            }
        }
        
        self.evasion_techniques = {
            "1": {
                "name": "Fragment Packets",
                "cmd": "-f",
                "description": "Split packets into smaller ones"
            },
            "2": {
                "name": "Specify MTU",
                "cmd": "--mtu 24",
                "description": "Custom packet size"
            },
            "3": {
                "name": "Decoy Scan",
                "cmd": "-D RND:10",
                "description": "Hide scan with decoys"
            },
            "4": {
                "name": "Idle Zombie Scan",
                "cmd": "-sI",
                "description": "Ultra-stealth scan"
            },
            "5": {
                "name": "Source Port Manipulation",
                "cmd": "--source-port 53",
                "description": "Fake source port"
            },
            "6": {
                "name": "Data Length Control",
                "cmd": "--data-length 25",
                "description": "Add random data to packets"
            },
            "7": {
                "name": "MAC Address Spoofing",
                "cmd": "--spoof-mac 0",
                "description": "Random MAC address"
            },
            "8": {
                "name": "Bad Checksum",
                "cmd": "--badsum",
                "description": "Detect packet filtering"
            }
        }

        self.timing_templates = {
            "1": {"name": "Paranoid", "cmd": "-T0"},
            "2": {"name": "Sneaky", "cmd": "-T1"},
            "3": {"name": "Polite", "cmd": "-T2"},
            "4": {"name": "Normal", "cmd": "-T3"},
            "5": {"name": "Aggressive", "cmd": "-T4"},
            "6": {"name": "Insane", "cmd": "-T5"}
        }

        self.vuln_categories = {
            "Web Applications": [
                ("http-sql-injection", "SQL Injection Scanner"),
                ("http-shellshock", "Shellshock Vulnerability"),
                ("http-csrf", "CSRF Detection"),
                ("http-vuln-cve2014-3704", "Drupalgeddon"),
                ("http-vuln-cve2017-5638", "Apache Struts RCE")
            ],
            "Network Services": [
                ("ssl-heartbleed", "Heartbleed Detection"),
                ("smb-vuln-ms17-010", "EternalBlue Scanner"),
                ("rdp-vuln-ms12-020", "RDP Vulnerability"),
                ("smtp-vuln-cve2010-4344", "Exim Heap Overflow")
            ],
            "Authentication": [
                ("ftp-vsftpd-backdoor", "vsFTPd Backdoor"),
                ("ssh-brute", "SSH Brute Force"),
                ("http-form-brute", "HTTP Form Bruteforce")
            ]
        }
def print_banner(self):
    banner = """
\033[96m╔═══════════════════════════════════════════════════════════════╗
║  _   _ __  __          _____   _____                           ║
║ | \ | |  \/  |   /\   |  __ \ / ____|                         ║
║ |  \| | \  / |  /  \  | |__) | |  __  ___ __ _ _ __  _ __    ║
║ | . ` | |\/| | / /\ \ |  ___/| | |_ |/ __/ _` | '_ \| '_ \   ║
║ | |\  | |  | |/ ____ \| |    | |__| | (_| (_| | | | | | | |  ║
║ |_| \_|_|  |_/_/    \_\_|     \_____|\___\__,_|_| |_|_| |_|  ║
║                                                               ║
║           Advanced Vulnerability Scanner for Kali             ║
╚═══════════════════════════════════════════════════════════════╝\033[0m
"""
    print(banner)



def add_target(self):
    target = input("\033[93m[+] Enter target IP or domain: \033[0m")
    if target:
        self.targets.append(target)
        print(f"\033[92m[✓] Target added: {target}\033[0m")
    else:
        print("\033[91m[!] Invalid target.\033[0m")
def remove_target(self):
    target = input("\033[93m[+] Enter target IP or domain to remove: \033[0m")
    if target in self.targets:
        self.targets.remove(target)
        print(f"\033[92m[✓] Target removed: {target}\033[0m")
    else:
        print("\033[91m[!] Target not found.\033[0m")
def list_targets(self):
    if not self.targets:
        print("\033[91m[!] No targets added.\033[0m")
    else:
        print("\033[94m[+] List of targets:\033[0m")
        for idx, target in enumerate(self.targets, 1):
            print(f"{idx}. {target}")
def configure_port_scan(self) -> dict:
    print("\n\033[95m[*] Port Scan Configuration:\033[0m")
    print("\n\033[94m[+] Available Port Scan Techniques:\033[0m")
    for key, technique in self.port_scan_techniques.items():
        print(f"{key}. {technique['name']} ({technique['description']})")
    
    scan_type = input("\n\033[93m[+] Select scan technique (1-7): \033[0m")
    port_range = input("\033[93m[+] Enter port range (e.g., 1-1000 or - for all ports): \033[0m")
    
    print("\n\033[94m[+] Available Evasion Techniques:\033[0m")
    for key, technique in self.evasion_techniques.items():
        print(f"{key}. {technique['name']} ({technique['description']})")
    
    evasion = input("\n\033[93m[+] Select evasion technique (1-8, or Enter to skip): \033[0m")
    
    print("\n\033[94m[+] Available Timing Templates:\033[0m")
    for key, template in self.timing_templates.items():
        print(f"{key}. {template['name']}")
    
    timing = input("\n\033[93m[+] Select timing template (1-6): \033[0m")
    
    scan_config = {
        'scan_type': self.port_scan_techniques.get(scan_type, self.port_scan_techniques['1'])['cmd'],
        'ports': '-p-' if port_range == '-' else f'-p{port_range}',
        'evasion': self.evasion_techniques.get(evasion, {'cmd': ''})['cmd'],
        'timing': self.timing_templates.get(timing, self.timing_templates['3'])['cmd']
    }
    
    return scan_config
def run_port_scan(self, scan_config: dict):
    if not self.targets:
        print("\033[91m[!] No targets available. Please add targets first.\033[0m")
        return
    
    print("\n\033[95m[*] Starting Port Scan...\033[0m")
    scan_timestamp = datetime.datetime.now()
    scan_results = {}
    
    for target in self.targets:
        print(f"\n\033[94m[+] Scanning target: {target}\033[0m")
        
        cmd = [
            "nmap",
            scan_config['scan_type'],
            scan_config['ports'],
            scan_config['timing']
        ]
        
        if scan_config['evasion']:
            cmd.append(scan_config['evasion'])
        
        cmd.append("-v")  # Verbose output
        cmd.append(target)
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
                    
            scan_results[target] = {
                'command': ' '.join(cmd),
                'timestamp': str(scan_timestamp),
                'output': output
            }
            
        except subprocess.CalledProcessError as e:
            print(f"\033[91m[!] Error scanning {target}: {e}\033[0m")
    
    self.scan_history.append({
        'type': 'port_scan',
        'timestamp': str(scan_timestamp),
        'targets': self.targets.copy(),
        'config': scan_config,
        'results': scan_results
    })
    
    print("\n\033[92m[✓] Port scan completed successfully\033[0m")
def print_menu(self):
    menu = """
\033[95m[*] Available Options:\033[0m
1. Add Target
2. Remove Target
3. List Targets
4. Port Scan
5. Vulnerability Scan
6. View Scan History
7. Exit
"""
    print(menu)

def execute_option(self, option: str):
    if option == '1':
        self.add_target()
    elif option == '2':
        self.remove_target()
    elif option == '3':
        self.list_targets()
    elif option == '4':
        scan_config = self.configure_port_scan()
        self.run_port_scan(scan_config)
    elif option == '5':
        print("\033[93m[*] Vulnerability Scan not implemented yet.\033[0m")
    elif option == '6':
        print("\033[93m[*] View Scan History not implemented yet.\033[0m")
    elif option == '7':
        sys.exit("\033[92m[✓] Exiting...\033[0m")
    else:
        print("\033[91m[!] Invalid option.\033[0m")

if __name__ == '__main__':
    scanner = NmapAdvancedScanner()
    scanner.print_banner()
    
    while True:
        scanner.print_menu()
        user_option = input("\033[93m[+] Select an option: \033[0m")
        scanner.execute_option(user_option)
