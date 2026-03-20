import sqlite3
import requests
import os

DB_NAME = 'security_engine.db'

def init_db():
    """Initializes the database and seeds it with the EICAR test signature."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create the table
    cursor.execute('''CREATE TABLE IF NOT EXISTS signatures 
                      (hash TEXT PRIMARY KEY, threat_name TEXT)''')
    
    # --- EICAR TEST DATA ---
    # This is the official SHA-256 hash of the EICAR test string.
    # String: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    eicar_name = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    
    cursor.execute("INSERT OR IGNORE INTO signatures VALUES (?, ?)", (eicar_hash, eicar_name))
    
    conn.commit()
    conn.close()
    print(f"[+] Database {DB_NAME} initialized with EICAR test signature.")

def populate_from_bazaar():
    """Fetches the latest 100 malware hashes from MalwareBazaar."""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {'query': 'get_recent', 'selector': '100'}
    
    try:
        response = requests.post(url, data=data, timeout=10)
        if response.status_code == 200:
            results = response.json().get('data', [])
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            new_count = 0
            for item in results:
                # Store SHA256 and the signature name
                h = item.get('sha256_hash')
                n = item.get('signature') or "Unknown Malware"
                if h:
                    cursor.execute("INSERT OR IGNORE INTO signatures VALUES (?, ?)", (h, n))
                    if cursor.rowcount > 0:
                        new_count += 1
            
            conn.commit()
            conn.close()
            return new_count
    except Exception as e:
        print(f"Update failed: {e}")
    return 0

if __name__ == "__main__":
    init_db()
    # Optional: Run populate to get real-world threats as well
    # count = populate_from_bazaar()
    # print(f"Added {count} recent malware signatures.")