#!/usr/bin/env python3
import os
import json
import subprocess
from pathlib import Path

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

def show_menu():
    clear_screen()
    print(BANNER)
    print("""
╔══════════════════════════════╗
║ Main Menu                    ║
╠══════════════════════════════╣
║ 1. Add Targets               ║
║ 2. Edit Targets              ║
║ 3. Delete Targets            ║
║ 4. List Targets              ║
║ 5. Select Scan Type          ║
║ 6. Run Scan                  ║
║ 7. View Scan History         ║
║ 8. Update This Gun           ║
║ 9. Exit                      ║
╚══════════════════════════════╝
""")

def load_targets():
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {'targets': [], 'scan_history': []}

def save_targets(data):
    CONFIG_FILE.write_text(json.dumps(data, indent=2))

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def add_targets(data):
    targets = input("Enter IPs/Domains (comma-separated): ").split(',')
    for t in targets:
        target = t.strip()
        if target and target not in data['targets']:
            data['targets'].append({'address': target, 'notes': ''})
    save_targets(data)

def edit_targets(data):
    list_targets(data)
    try:
        idx = int(input("Enter target number to edit: ")) - 1
        new_target = input("New IP/Domain: ").strip()
        new_note = input("Notes: ").strip()
        if 0 <= idx < len(data['targets']):
            data['targets'][idx]['address'] = new_target
            data['targets'][idx]['notes'] = new_note
            save_targets(data)
    except (ValueError, IndexError):
        pass

def delete_targets(data):
    list_targets(data)
    try:
        idx = int(input("Enter target number to delete: ")) - 1
        if 0 <= idx < len(data['targets']):
            del data['targets'][idx]
            save_targets(data)
    except (ValueError, IndexError):
        pass

def list_targets(data):
    print("\n╔════════════ Target List ════════════╗")
    for i, target in enumerate(data['targets'], 1):
        print(f"║ {i}. {target['address'].ljust(20)} - {target['notes']}")
    print("╚══════════════════════════════════════╝\n")

def select_scan_type():
    clear_screen()
    print("╔════════════ Scan Types ════════════╗")
    for num, profile in SCAN_PROFILES.items():
        print(f"║ {num}. {profile['name'].ljust(18)} - {profile['desc']}")
    print("╚════════════════════════════════════╝")
    
    try:
        choice = int(input("\nSelect scan type: "))
        if choice == 6:
            custom = input("Enter custom Nmap options: ")
            return SCAN_PROFILES[6]['command'].format(custom=custom)
        return SCAN_PROFILES.get(choice, SCAN_PROFILES[1])['command']
    except (ValueError, KeyError):
        return SCAN_PROFILES[1]['command']

def select_evasion_options():
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
        return ""

def select_vuln_scripts():
    clear_screen()
    print("╔════════════ Vulnerability Script Options ════════════╗")
    for num, script in VULN_SCRIPTS.items():
        print(f"║ {num}. {script['name'].ljust(25)} ║")
    print("╚════════════════════════════════════════════════════╝")
    
    try:
        choice = int(input("\nSelect vulnerability scan type: "))
        return VULN_SCRIPTS.get(choice, VULN_SCRIPTS[1])['script']
    except (ValueError, KeyError):
        return VULN_SCRIPTS[1]['script']

def run_scan(data, command):
    if not data['targets']:
        input("No targets! Add some first.")
        return
    
    list_targets(data)
    targets = input("Enter target numbers (comma-separated/all): ").strip()
    
    # Ask about evasion techniques
    use_evasion = input("Do you want to use network evasion techniques? (y/n): ").lower()
    evasion_opts = select_evasion_options() if use_evasion == 'y' else ""
    
    # For vulnerability scans, ask about script type
    vuln_script = ""
    if "script" in command:
        vuln_script = select_vuln_scripts()
    
    if targets.lower() == 'all':
        selected = data['targets']
    else:
        selected = [data['targets'][int(i)-1] for i in targets.split(',') if i.strip().isdigit()]
    
    # Ask for ports to scan
    ports = input("Enter ports to scan (e.g., 80,443 or leave blank for all ports): ").strip()
    if ports:
        command = command.format(custom=f"-p {ports}", target="{target}", evasion=evasion_opts, vuln_script=vuln_script)
    else:
        command = command.format(custom="", target="{target}", evasion=evasion_opts, vuln_script=vuln_script)

    for target in selected:
        full_command = command.format(target=target['address'])
        print(f"Running scan for {target['address']}...")
        subprocess.run(full_command.split())

def git_pull_update():
    os.system('git pull')

def main():
    data = load_targets()
    while True:
        show_menu()
        choice = input("\nChoose an option: ")
        
        if choice == '1':
            add_targets(data)
        elif choice == '2':
            edit_targets(data)
        elif choice == '3':
            delete_targets(data)
        elif choice == '4':
            list_targets(data)
        elif choice == '5':
            scan_command = select_scan_type()
        elif choice == '6':
            run_scan(data, scan_command)
        elif choice == '7':
            # Placeholder for scan history
            pass
        elif choice == '8':
            git_pull_update()
        elif choice == '9':
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
