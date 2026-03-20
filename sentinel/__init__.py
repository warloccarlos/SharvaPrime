from .database import init_db, populate_from_bazaar
from .gui import AntiVirusApp, load_custom_font
import os, sys

def main():
    init_db()
    print("Updating malware signatures...")
    count = populate_from_bazaar()
    print(f"Database updated with {count} new threats.")

    font_file = os.path.join(getattr(sys, '_MEIPASS', os.getcwd()), "assets", "FuturaLightCondensedBT.ttf")
    load_custom_font(font_file)
    font_file = os.path.join(getattr(sys, '_MEIPASS', os.getcwd()), "assets", "DIN.ttf")
    load_custom_font(font_file)

    app = AntiVirusApp()
    app.mainloop()
    app.pulse_logo()