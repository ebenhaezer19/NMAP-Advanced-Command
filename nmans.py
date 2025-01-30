import os
import subprocess
import json
import datetime

class NmapManager:
    def __init__(self):
        self.targets = []
        self.scan_history = []
        self.evasion_options = [
            "-D RND:10",  # Decoy scan
            "-S spoofed-ip",  # Source IP spoofing
            "--data-length 100",  # Append random data to packets
            "--ttl 50",  # Set custom TTL value
        ]
    
    def show_banner(self):
        banner = """
███╗   ██╗███╗   ███╗ █████╗ ███╗   ██╗███████╗
████╗  ██║████╗ ████║██╔══██╗████╗  ██║██╔════╝
██╔██╗ ██║██╔████╔██║███████║██╔██╗ ██║███████╗
██║╚██╗██║██║╚██╔╝██║██╔══██║██║╚██╗██║╚════██║
██║ ╚████║██║ ╚═╝ ██║██║  ██║██║ ╚████║███████║
╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝
        Nmap Manager v1.0 - Manage Your Scans
"""
        print(banner)

    def add_target(self, target):
        if target not in self.targets:
            self.targets.append(target)
            print(f"Target {target} added.")
        else:
            print("Target already exists.")
    
    def remove_target(self, target):
        if target in self.targets:
            self.targets.remove(target)
            print(f"Target {target} removed.")
        else:
            print("Target not found.")
    
    def list_targets(self):
        print("Current targets:")
        for target in self.targets:
            print(f" - {target}")
    
    def run_scan(self, scan_type="-sS", evasion=None, output_file=None):
        if not self.targets:
            print("No targets available.")
            return
        
        cmd = ["nmap", scan_type]
        if evasion:
            cmd.append(evasion)
            
        # Add output file option if specified
        if output_file:
            cmd.extend(["-oN", output_file])
            
        cmd.extend(self.targets)
        
        print(f"Running scan: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        scan_data = {
            "timestamp": str(datetime.datetime.now()),
            "command": " ".join(cmd),
            "output": result.stdout,
            "output_file": output_file
        }
        self.scan_history.append(scan_data)
        
        print(result.stdout)
        if output_file:
            print(f"Scan results saved to: {output_file}")
    
    def save_scan_history(self, filename="scan_history.json"):
        with open(filename, "w") as f:
            json.dump(self.scan_history, f, indent=4)
        print(f"Scan history saved to {filename}")
    
    def load_scan_history(self, filename="scan_history.json"):
        if os.path.exists(filename):
            with open(filename, "r") as f:
                self.scan_history = json.load(f)
            print("Scan history loaded.")
        else:
            print("No scan history file found.")
    
    def list_scan_history(self):
        for i, scan in enumerate(self.scan_history):
            print(f"[{i+1}] {scan['timestamp']} - {scan['command']}")
            if scan.get('output_file'):
                print(f"    Output file: {scan['output_file']}")
    
    def clear_scan_history(self):
        self.scan_history = []
        print("Scan history cleared.")
    
    def git_pull_update(self):
        print("Updating the script from Git repository...")
        result = subprocess.run(["git", "pull"], capture_output=True, text=True)
        print(result.stdout)
    
if __name__ == "__main__":
    manager = NmapManager()
    manager.show_banner()
    manager.load_scan_history()
    
    while True:
        print("\nNmap Manager")
        print("1. Add Target")
        print("2. Remove Target")
        print("3. List Targets")
        print("4. Run Scan")
        print("5. List Scan History")
        print("6. Save Scan History")
        print("7. Clear Scan History")
        print("8. Update Script")
        print("9. Exit")
        
        choice = input("Choose an option: ")
        
        if choice == "1":
            target = input("Enter target IP or domain: ")
            manager.add_target(target)
        elif choice == "2":
            target = input("Enter target to remove: ")
            manager.remove_target(target)
        elif choice == "3":
            manager.list_targets()
        elif choice == "4":
            scan_type = input("Enter scan type (default -sS): ") or "-sS"
            evasion = input("Enter evasion option (or leave blank): ")
            output_file = input("Enter output file name (or leave blank): ")
            manager.run_scan(scan_type, evasion, output_file)
        elif choice == "5":
            manager.list_scan_history()
        elif choice == "6":
            manager.save_scan_history()
        elif choice == "7":
            manager.clear_scan_history()
        elif choice == "8":
            manager.git_pull_update()
        elif choice == "9":
            break
        else:
            print("Invalid choice, try again.")