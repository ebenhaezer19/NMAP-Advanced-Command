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
║ 8. Update Tools from GitHub  ║
║ 9. Exit                      ║
╚══════════════════════════════╝
""")

CONFIG_FILE = Path.home() / '.nmap_manager.json'
SCAN_PROFILES = {
    1: {'name': 'Quick Scan', 'command': 'nmap -T4 -F {target}', 'desc': 'Fast scan of most common ports'},
    2: {'name': 'Full Scan', 'command': 'nmap -p- -sV -O -T4 {target}', 'desc': 'Full port scan with OS/service detection'},
    3: {'name': 'Stealth Scan', 'command': 'nmap -sS -sV -T4 {target}', 'desc': 'SYN stealth scan with service detection'},
    4: {'name': 'UDP Scan', 'command': 'nmap -sU -T4 {target}', 'desc': 'UDP port scan (requires root)'},
    5: {'name': 'Vulnerability Scan', 'command': 'nmap --script vuln {target}', 'desc': 'Common vulnerability checks'},
    6: {'name': 'Custom Scan', 'command': 'nmap {custom} {target}', 'desc': 'Enter your own Nmap options'}
}

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

def run_scan(data, command):
    if not data['targets']:
        input("No targets! Add some first.")
        return
    
    list_targets(data)
    targets = input("Enter target numbers (comma-separated/all): ").strip()
    
    if targets.lower() == 'all':
        selected = data['targets']
    else:
        selected = [data['targets'][int(i)-1] for i in targets.split(',') if i.strip().isdigit()]
    
    for target in selected:
        cmd = command.format(target=target['address'])
        data['scan_history'].append(cmd)
        save_targets(data)
        
        # Run scan and save output to a file
        scan_output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Ask for custom filename
        filename = input("Enter filename to save the result (without extension): ").strip()
        if not filename:
            filename = f"scan_{target['address']}"
        
        file_path = Path(f"{filename}.txt")
        with open(file_path, 'w') as f:
            f.write(scan_output.stdout)
        
        print(f"Scan result saved to {file_path}")
        input("\nPress Enter to continue...")

def view_history(data):
    clear_screen()
    print("╔════════════ Scan History ════════════╗")
    for i, cmd in enumerate(data['scan_history'], 1):
        print(f"║ {i}. {cmd}")
    print("╚═══════════════════════════════════════╝")
    input("\nPress Enter to return...")

def update_tools_from_github():
    clear_screen()
    print("Updating tools from GitHub...")
    try:
        subprocess.run(['git', 'pull'], check=True)
        print("Tools updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating tools: {e}")
    input("\nPress Enter to continue...")

def main():
    data = load_targets()
    current_scan_cmd = SCAN_PROFILES[1]['command']
    
    while True:
        show_menu()
        choice = input("Select option: ").strip()
        
        if choice == '1':
            add_targets(data)
        elif choice == '2':
            edit_targets(data)
        elif choice == '3':
            delete_targets(data)
        elif choice == '4':
            list_targets(data)
            input("\nPress Enter to continue...")
        elif choice == '5':
            current_scan_cmd = select_scan_type()
        elif choice == '6':
            run_scan(data, current_scan_cmd)
        elif choice == '7':
            view_history(data)
        elif choice == '8':
            update_tools_from_github()
        elif choice == '9':
            print("Exiting...")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
