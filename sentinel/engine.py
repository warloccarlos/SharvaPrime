# sentinel_agent/engine.py
import os
import sys
import platform
import hashlib
import sqlite3
import shutil
from datetime import datetime
from plyer import notification

QUARANTINE_DIR = os.path.join(os.getcwd(), "mokshah_quarantine")

if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def get_system_drives():
    """Returns a list of root paths for all connected drives."""
    if platform.system() == "Windows":
        import string
        return [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    return ["/"] # Linux/macOS root

def check_for_threat(file_path):
    """Calculates SHA-256 of a file and queries the threat DB."""
    sha256_hash = hashlib.sha256()
    
    try:
        # Read file in binary mode in chunks to avoid memory crashes with large files
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        file_hash = sha256_hash.hexdigest()

        # Connect to your threat signature database
        # Replace 'signatures.db' with your actual database file
        conn = sqlite3.connect('security_engine.db')
        cursor = conn.cursor()
        
        # Look for the hash in the 'signature' table
        cursor.execute("SELECT threat_name FROM signatures WHERE hash=?", (file_hash,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0]  # Returns the name of the virus found
        return None

    except (PermissionError, OSError):
        # Skip files that are system-locked or inaccessible
        return None

def full_system_scan(callback_update_ui):
    drives = get_system_drives()
    threats_found = []
    
    # Define excluded paths (normalized for consistency)
    excluded_paths = [
        os.path.normpath("C:/Windows"),
        os.path.normpath("/proc"),
        os.path.normpath("/dev"),
        os.path.normpath("/sys")
    ]
    
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            # Check if the current root starts with any of our excluded paths
            current_root = os.path.normpath(root)
            if any(current_root.startswith(ex) for ex in excluded_paths):
                # Efficiently skip the entire directory and its subfolders
                dirs[:] = [] 
                continue

            for file in files:
                file_path = os.path.join(root, file)
                
                # Double-check for individual system files that might be locked
                try:
                    threat = check_for_threat(file_path)
                    if threat:
                        threats_found.append((file_path, threat))
                except Exception:
                    continue # Silent skip for busy system files
                
                if len(files) % 50 == 0:
                    callback_update_ui(f"Scanning: {file_path}")

    # ... [Notification logic stays the same] ...
    return threats_found

def quarantine_threat(file_path):
    """Moves a threat to a secure location and renames it to prevent execution."""
    try:
        filename = os.path.basename(file_path)
        # Append timestamp and .locked extension
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_name = f"{filename}_{timestamp}.locked"
        dest_path = os.path.join(QUARANTINE_DIR, new_name)
        
        shutil.move(file_path, dest_path)
        # Set permissions to read-only for extra safety (OS dependent)
        os.chmod(dest_path, 0o444) 
        return True
    except Exception as e:
        print(f"Quarantine failed: {e}")
        return False