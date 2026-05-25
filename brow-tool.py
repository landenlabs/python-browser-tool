#!/usr/bin/env python3
import os
import sys
import json
import argparse
from pathlib import Path

def get_extension_details(manifest_path):
    """Parses manifest.json and handles errors smoothly."""
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            
        name = data.get('name', 'Unknown')
        version = data.get('version', 'Unknown')
        description = data.get('description', 'No description provided.')
        
        # Simple cleanup if they are localized keys (e.g., __MSG_appName__)
        if name.startswith('__MSG_') and name.endswith('__'):
            name = f"{name} (Localized)"
        if description.startswith('__MSG_') and description.endswith('__'):
            description = f"{description} (Localized)"
            
        return name, version, description
    except Exception:
        return "Unreadable Manifest", "Unknown", "Could not parse JSON."

def scan_chrome_directory(chrome_dir):
    """
    Scans the Chrome folder specifically targeting profiles and their underlying extensions.
    """
    root_path = Path(chrome_dir)
    if not root_path.exists():
        print(f"[-] Error: The path '{chrome_dir}' does not exist.")
        sys.exit(1)

    print(f"[*] Scanning for extensions in: {root_path}\n")
    
    # Track metrics
    extensions_found = 0
    
    # Iterate through items in the Chrome user data directory
    for profile_item in root_path.iterdir():
        # Profiles are directories; standard profiles are named 'Default' or 'Profile X'
        if profile_item.is_dir() and (profile_item.name == 'Default' or profile_item.name.startswith('Profile')):
            extensions_dir = profile_item / "Extensions"
            
            if extensions_dir.exists() and extensions_dir.is_dir():
                print(f"=== Profile: {profile_item.name} ===")
                profile_has_extensions = False
                
                # Dig into each Extension ID folder
                for ext_id_dir in extensions_dir.iterdir():
                    if ext_id_dir.is_dir():
                        # Extensions have version subfolders which house the manifest.json
                        for version_dir in ext_id_dir.iterdir():
                            manifest_file = version_dir / "manifest.json"
                            if manifest_file.exists():
                                profile_has_extensions = True
                                extensions_found += 1
                                
                                name, version, desc = get_extension_details(manifest_file)
                                
                                print(f"  Name        : {name}")
                                print(f"  Version     : {version}")
                                print(f"  Description : {desc}")
                                print(f"  Profile     : {profile_item.name} (Enabled/Installed)")
                                print(f"  Path        : {manifest_file}")
                                print("-" * 50)
                
                if not profile_has_extensions:
                    print("  (No user extensions found in this profile)")
                    print("-" * 50)
                print()

    if extensions_found == 0:
        print("[-] No active profile extensions detected. (Component updates ignored)")

def main():
    parser = argparse.ArgumentParser(description="Browser directory analysis and forensics tool.")
    parser.add_argument(
        '--summary', 
        action='store_true', 
        required=True, 
        help="Provide a summary of profiles and their installed extensions."
    )
    parser.add_argument(
        '--chrome', 
        required=True, 
        help="Path to the Google Chrome User Data directory."
    )
    
    args = parser.parse_args()

    if args.summary:
        scan_chrome_directory(args.chrome)

if __name__ == "__main__":
    main()
    