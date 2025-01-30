#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import json
import datetime
from typing import List, Dict
from xml.etree import ElementTree as ET

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
                scan_config['evasion'],
                scan_config['timing'],
                target
            ]

            try:
                scan_output = subprocess.check_output(cmd, stderr=subprocess.PIPE).decode()
                scan_results[target] = scan_output
                self.vulnerability_scan(scan_output)
            except subprocess.CalledProcessError as e:
                print(f"\033[91m[!] Scan failed for {target}: {e}\033[0m")

        self.scan_history.append({
            'timestamp': scan_timestamp,
            'results': scan_results
        })

    def vulnerability_scan(self, scan_result: str):
        detected_vulnerabilities = []
        for category in self.vuln_categories.values():
            for vuln_id, vuln_name in category:
                if vuln_id in scan_result:
                    detected_vulnerabilities.append(f"Found {vuln_name}")
        
        if detected_vulnerabilities:
            print("\n\033[91m[!] Potential Vulnerabilities Detected:\033[0m")
            for vuln in detected_vulnerabilities:
                print(f" - {vuln}")
        else:
            print("\n\033[92m[✓] No obvious vulnerabilities detected in initial scan\033[0m")

    def run_vulnerability_scan(self):
        if not self.targets:
            print("\033[91m[!] No targets available. Add targets first.\033[0m")
            return

        print("\n\033[95m[*] Vulnerability Scan Configuration:\033[0m")
        print("\n\033[94m[+] Select Vulnerability Category:\033[0m")
        categories = list(self.vuln_categories.keys())
        for idx, category in enumerate(categories, 1):
            print(f"{idx}. {category}")
        print(f"{len(categories)+1}. All Categories")

        choice = input(f"\n\033[93m[+] Select category (1-{len(categories)+1}): \033[0m")

        selected_scripts = []
        if choice == str(len(categories)+1):
            for category in self.vuln_categories.values():
                selected_scripts.extend([script[0] for script in category])
        elif choice.isdigit() and 1 <= int(choice) <= len(categories):
            category = categories[int(choice)-1]
            selected_scripts = [script[0] for script in self.vuln_categories[category]]
        else:
            print("\033[91m[!] Invalid selection.\033[0m")
            return

        if not selected_scripts:
            print("\033[91m[!] No scripts selected.\033[0m")
            return

        script_str = ",".join(selected_scripts)
        print(f"\n\033[94m[+] Running scripts: {script_str}\033[0m")

        scan_timestamp = datetime.datetime.now()
        scan_results = {}

        for target in self.targets:
            print(f"\n\033[94m[+] Starting Vulnerability Scan on {target}...\033[0m")
            
            cmd = [
                "nmap",
                "--script", script_str,
                "-oX", "-",
                target
            ]

            try:
                xml_output = subprocess.check_output(cmd, stderr=subprocess.PIPE).decode()
                scan_results[target] = xml_output
                self.parse_vulnerability_results(xml_output)
                
            except subprocess.CalledProcessError as e:
                error_msg = f"Scan failed for {target}: {e.stderr.decode().strip()}"
                print(f"\033[91m[!] {error_msg}\033[0m")
                scan_results[target] = error_msg

        self.scan_history.append({
            'timestamp': scan_timestamp,
            'results': scan_results
        })

    def parse_vulnerability_results(self, xml_data: str):
        try:
            root = ET.fromstring(xml_data)
            vuln_found = False
            
            for host in root.findall("host"):
                address = host.find("address").get("addr")
                hostnames = host.findall("hostnames/hostname")
                hostname = hostnames[0].get("name") if hostnames else address
                
                print(f"\n\033[91m[ Results for {hostname} ]\033[0m")
                
                for port in host.findall("ports/port"):
                    portid = port.get("portid")
                    protocol = port.get("protocol")
                    service = port.find("service").get("name") if port.find("service") else "unknown"
                    
                    for script in port.findall("script"):
                        script_id = script.get("id")
                        output = script.get("output")
                        
                        vuln_name = "Unknown Vulnerability"
                        for category in self.vuln_categories.values():
                            for vuln in category:
                                if vuln[0] == script_id:
                                    vuln_name = vuln[1]
                                    break
                        
                        print(f"\n\033[93m[!] Vulnerability: {vuln_name}")
                        print(f"    Port: {portid}/{protocol} ({service})")
                        print(f"    Script: {script_id}")
                        print(f"    Details:\n{output}\033[0m")
                        vuln_found = True

            if not vuln_found:
                print("\033[92m[✓] No vulnerabilities found in detailed scan\033[0m")
                
        except ET.ParseError:
            print("\033[91m[!] Failed to parse XML results\033[0m")

    def view_scan_history(self):
        if not self.scan_history:
            print("\033[91m[!] No scan history available.\033[0m")
        else:
            print("\033[94m[+] Scan History:\033[0m")
            for idx, scan in enumerate(self.scan_history, 1):
                print(f"\nScan {idx} - {scan['timestamp']}")
                for target, result in scan['results'].items():
                    print(f"\n[+] Target: {target}")
                    print(result)

def print_menu():
    menu = """
    \033[96m
    1. Add Target
    2. Remove Target
    3. List Targets
    4. Run Port Scan
    5. Vulnerability Scan
    6. Scan History
    0. Exit
    \033[0m
    """
    print(menu)

def execute_option(option, scanner):
    if option == "1":
        scanner.add_target()
    elif option == "2":
        scanner.remove_target()
    elif option == "3":
        scanner.list_targets()
    elif option == "4":
        scan_config = scanner.configure_port_scan()
        scanner.run_port_scan(scan_config)
    elif option == "5":
        scanner.run_vulnerability_scan()
    elif option == "6":
        scanner.view_scan_history()
    elif option == "0":
        print("\033[92mExiting program...\033[0m")
        sys.exit()
    else:
        print("\033[91mInvalid option, please try again.\033[0m")

if __name__ == "__main__":
    scanner = NmapAdvancedScanner()
    scanner.print_banner()
    while True:
        print_menu()
        user_option = input("\033[93m[+] Select an option: \033[0m")
        execute_option(user_option, scanner)