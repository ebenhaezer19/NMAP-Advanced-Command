#!/usr/bin/env python3
import os
import json
import subprocess
import shlex
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

BANNER = r"""
╔═══════════════════════════════════════════════════╗
║  ███╗   ██╗███╗   ███╗ █████╗ ███╗   ██╗███████╗  ║
║  ████╗  ██║████╗ ████║██╔══██╗████╗  ██║██╔════╝  ║
║  ██╔██╗ ██║██╔████╔██║███████║██╔██╗ ██║███████╗  ║
║  ██║╚██╗██║██║╚██╔╝██║██╔══██║██║╚██╗██║╚════██║  ║
║  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║ ╚████║███████║  ║
║  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝  ║
╠═══════════════════════════════════════════════════╣
║          Nmap Management Assistant Nexus          ║
╚═══════════════════════════════════════════════════╝
"""

VULN_SCRIPTS = {
    1: {'name': 'Default vuln scripts', 'script': 'vuln'},
    2: {'name': 'SQL Injection', 'script': 'http-sql-injection,mysql-vuln*,ms-sql-info,ms-sql-empty-password'},
    3: {'name': 'Cross-Site Scripting', 'script': 'http-stored-xss,http-phpself-xss,http-unsafe-output-escaping'},
    4: {'name': 'Remote Code Execution', 'script': 'http-rce-jenkins,http-vuln-cve2017-5638'},
    5: {'name': 'Authentication Bypass', 'script': 'auth-spoof,http-auth-finder,http-config-backup'},
    6: {'name': 'Service Vulnerabilities', 'script': 'ftp-vuln*,http-vuln*,smtp-vuln*,ssh-auth-methods'},
    7: {'name': 'All Vulnerability Scripts', 'script': 'vuln,auth-spoof,http-*,ftp-*,smtp-*,ssh-*'}
}

EVASION_OPTIONS = {
    1: {'name': 'No Ping (-Pn)', 'option': '-Pn'},
    2: {'name': 'Fragmented IP (-f)', 'option': '-f'},
    3: {'name': 'Decoy Scan (-D)', 'option': '-D RND:5'},
    4: {'name': 'Timing Template (-T0)', 'option': '-T0'},
    5: {'name': 'Source Port Spoofing', 'option': '--source-port 53'},
    6: {'name': 'Multiple Options', 'option': '-Pn -f -D RND:3 -T2'}
}

CONFIG_FILE = Path.home() / '.nmap_manager.json'
SCAN_PROFILES = {
    1: {'name': 'Quick Scan', 'command': 'nmap -T4 -F {evasion} {target}', 'desc': 'Fast scan of most common ports'},
    2: {'name': 'Full Scan', 'command': 'nmap -p- -sV -O -T4 {evasion} {target}', 'desc': 'Full port scan with OS/service detection'},
    3: {'name': 'Stealth Scan', 'command': 'nmap -sS -sV -T4 {evasion} {target}', 'desc': 'SYN stealth scan with service detection'},
    4: {'name': 'UDP Scan', 'command': 'nmap -sU -T4 {evasion} {target}', 'desc': 'UDP port scan (requires root)'},
    5: {'name': 'Vulnerability Scan', 'command': 'nmap --script {vuln_script} {evasion} {target}', 'desc': 'Vulnerability checks'},
    6: {'name': 'Custom Scan', 'command': 'nmap {custom} {evasion} {target}', 'desc': 'Enter your own Nmap options'}
}

def clear_screen():
    """Clear the terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

class NmapManager:
    def __init__(self):
        self.data = self.load_targets()
        self.scan_command = SCAN_PROFILES[1]['command']

    def load_targets(self) -> Dict:
        """Load targets from config file with error handling."""
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE) as f:
                    return json.load(f)
        except (json.JSONDecodeError, PermissionError) as e:
            print(f"Error loading config: {e}")
        return {'targets': [], 'scan_history': []}

    def save_targets(self) -> None:
        """Save targets to config file with error handling."""
        try:
            CONFIG_FILE.write_text(json.dumps(self.data, indent=2))
        except (PermissionError, OSError) as e:
            print(f"Error saving config: {e}")

    def validate_target(self, target: str) -> bool:
        """Basic validation for target IP/domain."""
        return bool(target and not any(c in target for c in ';&|'))

    def validate_custom_options(self, options: str) -> bool:
        """Validate custom Nmap options for security."""
        forbidden_chars = {';', '&', '|', '>', '<', '$', '`', '"', "'", '\\'}
        return not any(char in options for char in forbidden_chars)

    def add_targets(self) -> None:
        """Add new targets with input validation."""
        targets = input("Enter IPs/Domains (comma-separated): ").split(',')
        for t in targets:
            target = t.strip()
            if self.validate_target(target) and target not in [t['address'] for t in self.data['targets']]:
                self.data['targets'].append({'address': target, 'notes': ''})
        self.save_targets()

    def edit_targets(self) -> None:
        """Edit existing targets with validation."""
        self.list_targets()
        try:
            idx = int(input("Enter target number to edit: ")) - 1
            if 0 <= idx < len(self.data['targets']):
                new_target = input("New IP/Domain (or press Enter to keep current): ").strip()
                new_note = input("Notes: ").strip()
                
                if new_target and self.validate_target(new_target):
                    self.data['targets'][idx]['address'] = new_target
                self.data['targets'][idx]['notes'] = new_note
                self.save_targets()
            else:
                print("Invalid target number!")
        except ValueError:
            print("Please enter a valid number!")

    def delete_targets(self) -> None:
        """Delete targets with confirmation."""
        self.list_targets()
        try:
            idx = int(input("Enter target number to delete: ")) - 1
            if 0 <= idx < len(self.data['targets']):
                target = self.data['targets'][idx]
                confirm = input(f"Are you sure you want to delete {target['address']}? (y/n): ")
                if confirm.lower() == 'y':
                    del self.data['targets'][idx]
                    self.save_targets()
            else:
                print("Invalid target number!")
        except ValueError:
            print("Please enter a valid number!")

    def list_targets(self) -> None:
        """Display all targets."""
        print("\n╔════════════ Target List ════════════╗")
        if not self.data['targets']:
            print("║ No targets found                    ║")
        else:
            for i, target in enumerate(self.data['targets'], 1):
                print(f"║ {i}. {target['address'].ljust(20)} - {target['notes']}")
        print("╚══════════════════════════════════════╝\n")

    def select_scan_type(self) -> str:
        """Select and return scan type command."""
        clear_screen()
        print("╔════════════ Scan Types ════════════╗")
        for num, profile in SCAN_PROFILES.items():
            print(f"║ {num}. {profile['name'].ljust(18)} - {profile['desc']}")
        print("╚════════════════════════════════════╝")
        
        try:
            choice = int(input("\nSelect scan type: "))
            if choice == 6:
                custom = input("Enter custom Nmap options: ")
                if self.validate_custom_options(custom):
                    return SCAN_PROFILES[6]['command'].format(custom=custom)
                else:
                    print("Invalid custom options!")
                    return SCAN_PROFILES[1]['command']
            return SCAN_PROFILES.get(choice, SCAN_PROFILES[1])['command']
        except (ValueError, KeyError):
            print("Invalid choice, using default scan type.")
            return SCAN_PROFILES[1]['command']

    def select_evasion_options(self) -> str:
        """Select and return evasion options."""
        clear_screen()
        print("╔════════════ Evasion Options ════════════╗")
        for num, option in EVASION_OPTIONS.items():
            print(f"║ {num}. {option['name'].ljust(20)} - {option['option']}")
        print("╚══════════════════════════════════════════╝")
        
        try:
            choice = int(input("\nSelect evasion option (0 for none): "))
            if choice == 0:
                return ""
            return EVASION_OPTIONS.get(choice, EVASION_OPTIONS[1])['option']
        except (ValueError, KeyError):
            print("Invalid choice, using no evasion options.")
            return ""

    def select_vuln_scripts(self) -> str:
        """Select and return vulnerability script options."""
        clear_screen()
        print("╔════════════ Vulnerability Script Options ════════════╗")
        for num, script in VULN_SCRIPTS.items():
            print(f"║ {num}. {script['name'].ljust(25)} ║")
        print("╚════════════════════════════════════════════════════╝")
        
        try:
            choice = int(input("\nSelect vulnerability scan type: "))
            return VULN_SCRIPTS.get(choice, VULN_SCRIPTS[1])['script']
        except (ValueError, KeyError):
            print("Invalid choice, using default vulnerability scripts.")
            return VULN_SCRIPTS[1]['script']

    def view_scan_history(self) -> None:
        """Display scan history."""
        clear_screen()
        print("\n╔════════════ Scan History ════════════╗")
        if not self.data.get('scan_history'):
            print("║ No scan history available            ║")
        else:
            for i, scan in enumerate(self.data['scan_history'], 1):
                status = "Success" if scan['success'] else "Failed"
                print(f"║ {i}. Target: {scan['target']}")
                print(f"║    Time: {scan['timestamp']}")
                print(f"║    Status: {status}")
                print(f"║    Command: {scan['command']}")
                print("║----------------------------------------║")
        print("╚══════════════════════════════════════╝")
        input("\nPress Enter to continue...")

    def run_scan(self) -> None:
        """Execute Nmap scan with safety checks."""
        if not self.data['targets']:
            print("No targets! Add some first.")
            input("Press Enter to continue...")
            return

        self.list_targets()
        targets = input("Enter target numbers (comma-separated/all): ").strip()
        
        try:
            selected_targets = []
            if targets.lower() == 'all':
                selected_targets = self.data['targets']
            else:
                indices = [int(i.strip())-1 for i in targets.split(',') if i.strip().isdigit()]
                selected_targets = [self.data['targets'][i] for i in indices if 0 <= i < len(self.data['targets'])]

            if not selected_targets:
                print("No valid targets selected!")
                return

            use_evasion = input("Use network evasion techniques? (y/n): ").lower() == 'y'
            evasion_opts = self.select_evasion_options() if use_evasion else ""
            
            vuln_script = ""
            if "script" in self.scan_command:
                vuln_script = self.select_vuln_scripts()
            
            ports = input("Enter ports to scan (blank for all): ").strip()
            custom_opts = f"-p {ports}" if ports else ""

            for target in selected_targets:
                if not self.validate_target(target['address']):
                    print(f"Skipping invalid target: {target['address']}")
                    continue

                command = self.scan_command.format(
                    custom=custom_opts,
                    target=shlex.quote(target['address']),
                    evasion=evasion_opts,
                    vuln_script=vuln_script
                )
                
                print(f"\nRunning scan for {target['address']}...")
                print(f"Command: {command}\n")
                
                try:
                    result = subprocess.run(
                        shlex.split(command),
                        capture_output=True,
                        text=True
                    )
                    print(result.stdout)
                    if result.stderr:
                        print("Errors:", result.stderr)
                        
                    # Save to scan history
                    self.data['scan_history'].append({
                        'target': target['address'],
                        'command': command,
                        'timestamp': datetime.now().isoformat(),
                        'success': result.returncode == 0
                    })
                    self.save_targets()
                    
                except subprocess.SubprocessError as e:
                    print(f"Error running scan: {e}")

        except ValueError:
            print("Please enter valid target numbers!")

    def git_pull_update(self) -> None:
        """Safely execute git pull."""
        try:
            result = subprocess.run(
                ['git', 'pull'],
                capture_output=True,
                text=True,
                check=True
            )
            print(result.stdout)
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            print(f"Error updating: {e}")

def main():
    nmap_manager = NmapManager()

    while True:
        clear_screen()
        print(BANNER)
        print("╔════════════ Main Menu ════════════╗")
        print("║ 1. Add Target                      ║")
        print("║ 2. Edit Target                     ║")
        print("║ 3. Delete Target                   ║")
        print("║ 4. View Target List                ║")
        print("║ 5. Run Scan                        ║")
        print("║ 6. View Scan History               ║")
        print("║ 7. Exit                            ║")
        print("╚════════════════════════════════════╝")

        choice = input("\nSelect an option: ").strip()
        
        if choice == '1':
            nmap_manager.add_targets()
        elif choice == '2':
            nmap_manager.edit_targets()
        elif choice == '3':
            nmap_manager.delete_targets()
        elif choice == '4':
            nmap_manager.list_targets()
        elif choice == '5':
            nmap_manager.run_scan()
        elif choice == '6':
            nmap_manager.view_scan_history()
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()