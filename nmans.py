#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import json
import datetime
from typing import List, Dict

class NmapVulnScanner:
    def __init__(self):
        self.targets = []
        self.scan_history = []
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
        
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        
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
        
    def print_menu(self):
        menu = """
\033[95m[*] Available Options:\033[0m
1. Add Target
2. Remove Target
3. List Targets
4. Select Vulnerability Scripts
5. Run Vulnerability Scan
6. View Scan History
7. Export Results
8. Clear Screen
9. Exit

"""
        print(menu)
        
    def add_target(self):
        target = input("\033[93m[+] Enter target IP/hostname: \033[0m")
        if target not in self.targets:
            self.targets.append(target)
            print(f"\033[92m[✓] Target {target} added successfully\033[0m")
        else:
            print("\033[91m[!] Target already exists\033[0m")
            
    def remove_target(self):
        if not self.targets:
            print("\033[91m[!] No targets available\033[0m")
            return
            
        print("\n\033[95m[*] Current Targets:\033[0m")
        for i, target in enumerate(self.targets, 1):
            print(f"{i}. {target}")
            
        try:
            choice = int(input("\n\033[93m[+] Enter target number to remove: \033[0m"))
            if 1 <= choice <= len(self.targets):
                removed = self.targets.pop(choice - 1)
                print(f"\033[92m[✓] Removed target: {removed}\033[0m")
            else:
                print("\033[91m[!] Invalid target number\033[0m")
        except ValueError:
            print("\033[91m[!] Please enter a valid number\033[0m")
            
    def list_targets(self):
        if not self.targets:
            print("\033[91m[!] No targets available\033[0m")
            return
            
        print("\n\033[95m[*] Current Targets:\033[0m")
        for i, target in enumerate(self.targets, 1):
            print(f"{i}. {target}")
            
    def select_vuln_scripts(self) -> List[str]:
        selected_scripts = []
        
        print("\n\033[95m[*] Available Vulnerability Scripts:\033[0m")
        for category, scripts in self.vuln_categories.items():
            print(f"\n\033[94m[+] {category}:\033[0m")
            for i, (script_id, script_name) in enumerate(scripts, 1):
                print(f"{i}. {script_name} ({script_id})")
                
        while True:
            try:
                choices = input("\n\033[93m[+] Enter script numbers (comma-separated) or 'all' for everything: \033[0m")
                if choices.lower() == 'all':
                    selected_scripts = [script[0] for scripts in self.vuln_categories.values() for script in scripts]
                    break
                elif choices.lower() == '':
                    break
                else:
                    nums = [int(x.strip()) for x in choices.split(',')]
                    all_scripts = [script for scripts in self.vuln_categories.values() for script in scripts]
                    for num in nums:
                        if 1 <= num <= len(all_scripts):
                            selected_scripts.append(all_scripts[num-1][0])
                    break
            except ValueError:
                print("\033[91m[!] Please enter valid numbers\033[0m")
                
        return selected_scripts
        
    def run_scan(self, selected_scripts: List[str]):
        if not self.targets:
            print("\033[91m[!] No targets available. Please add targets first.\033[0m")
            return
            
        if not selected_scripts:
            print("\033[91m[!] No vulnerability scripts selected. Please select scripts first.\033[0m")
            return
            
        print("\n\033[95m[*] Starting Vulnerability Scan...\033[0m")
        
        scan_timestamp = datetime.datetime.now()
        scan_results = {}
        
        for target in self.targets:
            print(f"\n\033[94m[+] Scanning target: {target}\033[0m")
            
            # Construct Nmap command
            cmd = [
                "nmap",
                "-sV",  # Version detection
                "-sS",  # SYN scan
                "--script",
                ",".join(selected_scripts),
                "-v",   # Verbose output
                target
            ]
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Real-time output
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.strip())
                        
                # Store results
                scan_results[target] = {
                    'command': ' '.join(cmd),
                    'timestamp': str(scan_timestamp),
                    'output': output
                }
                
            except subprocess.CalledProcessError as e:
                print(f"\033[91m[!] Error scanning {target}: {e}\033[0m")
                
        # Save to scan history
        self.scan_history.append({
            'timestamp': str(scan_timestamp),
            'targets': self.targets.copy(),
            'scripts': selected_scripts,
            'results': scan_results
        })
        
        print("\n\033[92m[✓] Scan completed successfully\033[0m")
        
    def view_scan_history(self):
        if not self.scan_history:
            print("\033[91m[!] No scan history available\033[0m")
            return
            
        print("\n\033[95m[*] Scan History:\033[0m")
        for i, scan in enumerate(self.scan_history, 1):
            print(f"\n\033[94m[+] Scan #{i}\033[0m")
            print(f"Timestamp: {scan['timestamp']}")
            print(f"Targets: {', '.join(scan['targets'])}")
            print(f"Scripts: {', '.join(scan['scripts'])}")
            
        while True:
            try:
                choice = input("\n\033[93m[+] Enter scan number to view details (or Enter to return): \033[0m")
                if choice == '':
                    break
                    
                scan_num = int(choice)
                if 1 <= scan_num <= len(self.scan_history):
                    scan = self.scan_history[scan_num - 1]
                    print("\n\033[95m[*] Detailed Scan Results:\033[0m")
                    for target, results in scan['results'].items():
                        print(f"\n\033[94m[+] Target: {target}\033[0m")
                        print(f"Command: {results['command']}")
                        print("Output:")
                        print(results['output'])
                else:
                    print("\033[91m[!] Invalid scan number\033[0m")
            except ValueError:
                print("\033[91m[!] Please enter a valid number\033[0m")
                
    def export_results(self):
        if not self.scan_history:
            print("\033[91m[!] No scan history to export\033[0m")
            return
            
        filename = input("\033[93m[+] Enter export filename (default: scan_results.json): \033[0m") or "scan_results.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_history, f, indent=4)
            print(f"\033[92m[✓] Results exported to {filename}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error exporting results: {e}\033[0m")
            
    def run(self):
        while True:
            self.print_banner()
            self.print_menu()
            
            choice = input("\033[93m[+] Enter your choice (1-9): \033[0m")
            
            if choice == '1':
                self.add_target()
            elif choice == '2':
                self.remove_target()
            elif choice == '3':
                self.list_targets()
            elif choice == '4':
                selected_scripts = self.select_vuln_scripts()
                if selected_scripts:
                    print(f"\033[92m[✓] Selected {len(selected_scripts)} scripts\033[0m")
            elif choice == '5':
                selected_scripts = self.select_vuln_scripts()
                self.run_scan(selected_scripts)
            elif choice == '6':
                self.view_scan_history()
            elif choice == '7':
                self.export_results()
            elif choice == '8':
                self.clear_screen()
            elif choice == '9':
                print("\n\033[92m[✓] Thank you for using Nmap Vulnerability Scanner. Goodbye!\033[0m")
                sys.exit(0)
            else:
                print("\033[91m[!] Invalid choice. Please try again.\033[0m")
                
            input("\n\033[93mPress Enter to continue...\033[0m")
            self.clear_screen()

if __name__ == "__main__":
    scanner = NmapVulnScanner()
    scanner.run()