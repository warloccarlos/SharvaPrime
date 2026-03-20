import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import os
import ctypes
import sys
from sentinel.engine import check_for_threat, full_system_scan, quarantine_threat

def load_custom_font(font_path):
    """Registers a .ttf font so the OS can see it while the app is running."""
    if not os.path.exists(font_path):
        return False
    
    # GDI32.dll allows us to add the font resource to the system cache
    FR_PRIVATE = 0x10
    path_buffer = ctypes.create_unicode_buffer(font_path)
    res = ctypes.windll.gdi32.AddFontResourceExW(path_buffer, FR_PRIVATE, 0)
    return res > 0

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class AntiVirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Sharva Prime MALWARE HUNTER")
        self.geometry("900x600")

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1a1a1a") # Darker sidebar
        self.sidebar.pack(side="left", fill="y")

        # The Logo (Using a Trident Unicode Symbol)
        self.logo_label = ctk.CTkLabel(
            self.sidebar, 
            text="🔱", 
            font=("Segoe UI", 50)
        )
        self.logo_label.pack(pady=(30, 0))

        # Create a container frame inside the sidebar for the title
        self.title_container = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.title_container.pack(pady=(0, 20))

        # "SHARVA" - Aggressive, Bold, Red
        self.label_sharva = ctk.CTkLabel(
            self.title_container, 
            text="SHARVA", 
            font=("Futura LtCn BT", 66), # Sharp, heavy font
            text_color="#FF4B4B"
        )
        self.label_sharva.pack(side="top")

        # "PRIME" - Sleek, Modern, White
        self.label_prime = ctk.CTkLabel(
            self.title_container, 
            text="PRIME", 
            font=("DIN", 52), # Sophisticated contrast
            text_color="#FFFFFF"
        )
        self.label_prime.pack(side="bottom")

        self.subtitle = ctk.CTkLabel(
            self.sidebar, 
            text="MALWARE HUNTER ENGINE v1.0", 
            font=("Courier New", 10, "bold"), 
            text_color="#555555"
        )
        self.subtitle.pack(pady=(0, 30))

        # Buttons
        self.btn_file = ctk.CTkButton(self.sidebar, text="Scan File", command=self.scan_file)
        self.btn_file.pack(pady=10, padx=20)

        self.btn_folder = ctk.CTkButton(self.sidebar, text="Scan Folder/Drive", command=self.scan_folder)
        self.btn_folder.pack(pady=10, padx=20)

        self.btn_full = ctk.CTkButton(self.sidebar, text="Full System Scan", command=self.start_full_scan_thread)
        self.btn_full.pack(pady=10, padx=20)

        self.threat_label = ctk.CTkLabel(self.sidebar, text="Threats Neutralized: 0", text_color="white")
        self.threat_label.pack(side="bottom", pady=20)

        # --- Main View ---
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(side="right", fill="both", expand=True, padx=20, pady=20)

        self.progress_bar = ctk.CTkProgressBar(self.main_container, mode="indeterminate")
        self.progress_bar.pack(fill="x", pady=(0, 10))
        self.progress_bar.set(0)

        self.log_box = ctk.CTkTextbox(self.main_container)
        self.log_box.pack(fill="both", expand=True)
        self.log_box.tag_config("danger", foreground="#FF4B4B")
        self.log_box.tag_config("success", foreground="#4BB543")

    def log(self, message, tag=None):
        self.log_box.insert("end", f"{message}\n", tag)
        self.log_box.see("end")

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.log(f"[*] Analyzing: {file_path}")
            threat = check_for_threat(file_path)
            if threat:
                self.handle_threat(file_path, threat)
            else:
                self.log("[+] File is clean.", "success")

    def scan_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.log(f">>> Scanning Target: {folder_path}")
            self.start_scan_thread(folder_path)

    def start_full_scan_thread(self):
        self.log(">>> Engaged: Full System Hunt...")
        self.start_scan_thread(None) # Passing None triggers full scan logic

    def start_scan_thread(self, target_path):
        self.progress_bar.start()
        # Toggle buttons to avoid conflicts
        self.btn_full.configure(state="disabled")
        self.btn_folder.configure(state="disabled")
        
        thread = threading.Thread(target=self.run_engine, args=(target_path,), daemon=True)
        thread.start()

    def run_engine(self, target_path):
        # If target_path is None, it scans all drives; otherwise just the folder
        if target_path:
            # Reusing the logic from full_system_scan but restricted to one path
            # For simplicity, we can pass target_path to a modified engine function
            threats = self.execute_custom_scan(target_path)
        else:
            threats = full_system_scan(self.log)
        
        self.after(0, self.finalize_scan, threats)

    def execute_custom_scan(self, path):
        """Internal helper for folder-specific scanning."""
        found = []
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                self.after(0, self.log, f"Scanning: {file_path}")
                threat = check_for_threat(file_path)
                if threat:
                    self.handle_threat(file_path, threat)
                    found.append(file_path)
        return found

    def handle_threat(self, file_path, threat_name):
        self.log(f"[!] MALWARE DETECTED: {threat_name} in {file_path}", "danger")
        if quarantine_threat(file_path):
            self.log(f"[+] Successfully Quarantined to 'shiva_prison'", "success")
        else:
            self.log(f"[-] Failed to isolate threat: {file_path}", "danger")

    def finalize_scan(self, threats):
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.btn_full.configure(state="normal")
        self.btn_folder.configure(state="normal")
        self.log(f"--- Scan Finished. {len(threats)} Threats Found ---")
        self.threat_label.configure(text=f"Threats Neutralized: {len(threats)}")
    
    def pulse_logo(self):
        #"""Makes the Trident logo glow slightly redder/whiter."""
        current_color = self.logo_label.cget("text_color")
        new_color = "#FF4B4B" if current_color != "#FF4B4B" else "#FFFFFF"
        self.logo_label.configure(text_color=new_color)
        self.after(1000, self.pulse_logo) # Pulse every second

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    app = AntiVirusApp()
    app.mainloop()