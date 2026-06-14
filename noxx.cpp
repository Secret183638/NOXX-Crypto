#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>
#include <filesystem>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

// Цвета
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"

// Константы
constexpr int KEY_SIZE = 32;
constexpr int IV_SIZE = 16;
constexpr int SALT_SIZE = 32;
constexpr int ITERATIONS = 100000;
constexpr int BUFFER_SIZE = 16 * 1024 * 1024; // 16MB буфер

// Скрытый ввод пароля
std::string getPassword(const std::string& prompt) {
    std::string password;
    std::cout << prompt << std::flush;
    
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    
    return password;
}

// Крипто-функции
class Crypto {
public:
    static bool deriveKey(const std::string& password, 
                          const unsigned char* salt,
                          unsigned char* key, 
                          unsigned char* iv) {
        return PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                                 salt, SALT_SIZE, ITERATIONS,
                                 EVP_sha256(), KEY_SIZE + IV_SIZE,
                                 key) == 1;
    }
    
    static bool encryptFile(const std::string& inputFile,
                           const std::string& outputFile,
                           const std::string& password) {
        auto start = std::chrono::high_resolution_clock::now();
        
        // Открываем входной файл
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cerr << RED << "[-] Cannot open: " << inputFile << RESET << std::endl;
            return false;
        }
        
        // Получаем размер
        in.seekg(0, std::ios::end);
        size_t fileSize = in.tellg();
        in.seekg(0, std::ios::beg);
        
        std::cout << BLUE << "[*] File size: " << (fileSize / 1024.0 / 1024.0) << " MB" << RESET << std::endl;
        
        // Читаем весь файл
        std::vector<unsigned char> plaintext(fileSize);
        in.read(reinterpret_cast<char*>(plaintext.data()), fileSize);
        in.close();
        
        // Генерируем соль
        unsigned char salt[SALT_SIZE];
        if (RAND_bytes(salt, SALT_SIZE) != 1) {
            std::cerr << RED << "[-] Salt generation failed" << RESET << std::endl;
            return false;
        }
        
        // Деривация ключа
        unsigned char key[KEY_SIZE + IV_SIZE];
        if (!deriveKey(password, salt, key, key + KEY_SIZE)) {
            std::cerr << RED << "[-] Key derivation failed" << RESET << std::endl;
            return false;
        }
        
        // Шифрование
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, key + KEY_SIZE);
        
        std::vector<unsigned char> ciphertext(plaintext.size() + 16);
        int outLen = 0, tmpLen = 0;
        
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen,
                         plaintext.data(), plaintext.size());
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &tmpLen);
        outLen += tmpLen;
        
        ciphertext.resize(outLen);
        EVP_CIPHER_CTX_free(ctx);
        
        // Записываем результат
        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            std::cerr << RED << "[-] Cannot create: " << outputFile << RESET << std::endl;
            return false;
        }
        
        // Заголовок файла
        uint32_t magic = 0x4E4F5858; // "NOXX"
        uint16_t version = 0x0001;
        out.write(reinterpret_cast<char*>(&magic), sizeof(magic));
        out.write(reinterpret_cast<char*>(&version), sizeof(version));
        out.write(reinterpret_cast<char*>(salt), SALT_SIZE);
        out.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
        
        out.close();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        double speed = fileSize / 1024.0 / 1024.0 / (duration.count() / 1000.0);
        
        std::cout << GREEN << "[+] Encrypted in " << duration.count() << " ms" << RESET << std::endl;
        std::cout << CYAN << "    Speed: " << speed << " MB/s" << RESET << std::endl;
        
        return true;
    }
    
    static bool decryptFile(const std::string& inputFile,
                           const std::string& outputFile,
                           const std::string& password) {
        auto start = std::chrono::high_resolution_clock::now();
        
        // Открываем зашифрованный файл
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cerr << RED << "[-] Cannot open: " << inputFile << RESET << std::endl;
            return false;
        }
        
        // Читаем заголовок
        uint32_t magic;
        uint16_t version;
        in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        in.read(reinterpret_cast<char*>(&version), sizeof(version));
        
        if (magic != 0x4E4F5858) {
            std::cerr << RED << "[-] Not a NOXX file" << RESET << std::endl;
            return false;
        }
        
        // Читаем соль
        unsigned char salt[SALT_SIZE];
        in.read(reinterpret_cast<char*>(salt), SALT_SIZE);
        
        // Читаем зашифрованные данные
        std::vector<unsigned char> ciphertext(
            (std::istreambuf_iterator<char>(in)),
            std::istreambuf_iterator<char>()
        );
        in.close();
        
        // Деривация ключа
        unsigned char key[KEY_SIZE + IV_SIZE];
        if (!deriveKey(password, salt, key, key + KEY_SIZE)) {
            std::cerr << RED << "[-] Key derivation failed" << RESET << std::endl;
            return false;
        }
        
        // Дешифрование
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, key + KEY_SIZE);
        
        std::vector<unsigned char> plaintext(ciphertext.size());
        int outLen = 0, tmpLen = 0;
        
        EVP_DecryptUpdate(ctx, plaintext.data(), &outLen,
                         ciphertext.data(), ciphertext.size());
        
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &tmpLen);
        EVP_CIPHER_CTX_free(ctx);
        
        if (ret != 1) {
            std::cerr << RED << "[-] Decryption failed! Wrong password?" << RESET << std::endl;
            return false;
        }
        
        outLen += tmpLen;
        plaintext.resize(outLen);
        
        // Записываем результат
        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            std::cerr << RED << "[-] Cannot create: " << outputFile << RESET << std::endl;
            return false;
        }
        
        out.write(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
        out.close();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        double speed = plaintext.size() / 1024.0 / 1024.0 / (duration.count() / 1000.0);
        
        std::cout << GREEN << "[+] Decrypted in " << duration.count() << " ms" << RESET << std::endl;
        std::cout << CYAN << "    Speed: " << speed << " MB/s" << RESET << std::endl;
        
        return true;
    }
};

void printBanner() {
    std::cout << CYAN << R"(
    ╔═════════════════════════════════════╗
    ║ ███╗   ██╗ ██████╗ ██╗  ██╗██╗  ██╗ ║
    ║ ████╗  ██║██╔═══██╗╚██╗██╔╝╚██╗██╔╝ ║
    ║ ██╔██╗ ██║██║   ██║ ╚███╔╝  ╚███╔╝  ║
    ║ ██║╚██╗██║██║   ██║ ██╔██╗  ██╔██╗  ║
    ║ ██║ ╚████║╚██████╔╝██╔╝ ██╗██╔╝ ██╗ ║
    ║ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ║
    ╚═════════════════════════════════════╝
    )" << RESET << std::endl;
    std::cout << YELLOW << "    AES-256-CBC | Fast & Secure" << RESET << std::endl;
    std::cout << std::endl;
}

void printUsage() {
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << GREEN << "noxx -c <input> <output>" << RESET << "   Encrypt file" << std::endl;
    std::cout << "  " << GREEN << "noxx -d <input> <output>" << RESET << "   Decrypt file" << std::endl;
    std::cout << "  " << GREEN << "noxx -h" << RESET << "                 Help" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << CYAN << "noxx -c secret.txt secret.enc" << RESET << std::endl;
    std::cout << "  " << CYAN << "noxx -d secret.enc secret.txt" << RESET << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    printBanner();
    
    int opt;
    int mode = 0;
    std::string inputFile, outputFile;
    
    while ((opt = getopt(argc, argv, "c:d:h")) != -1) {
        switch (opt) {
            case 'c':
                mode = 1;
                if (optind < argc) {
                    inputFile = optarg;
                    outputFile = argv[optind];
                    optind++;
                } else {
                    std::cerr << RED << "[-] Missing output file" << RESET << std::endl;
                    printUsage();
                    return 1;
                }
                break;
            case 'd':
                mode = 2;
                if (optind < argc) {
                    inputFile = optarg;
                    outputFile = argv[optind];
                    optind++;
                } else {
                    std::cerr << RED << "[-] Missing output file" << RESET << std::endl;
                    printUsage();
                    return 1;
                }
                break;
            case 'h':
                printUsage();
                return 0;
            default:
                printUsage();
                return 1;
        }
    }
    
    if (mode == 0 || inputFile.empty() || outputFile.empty()) {
        std::cerr << RED << "[-] Invalid arguments!" << RESET << std::endl;
        printUsage();
        return 1;
    }
    
    if (!std::filesystem::exists(inputFile)) {
        std::cerr << RED << "[-] File not found: " << inputFile << RESET << std::endl;
        return 1;
    }
    
    if (mode == 2 && !std::filesystem::exists(inputFile)) {
        std::cerr << RED << "[-] Input file not found" << RESET << std::endl;
        return 1;
    }
    
    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    RAND_poll();
    
    bool success = false;
    
    if (mode == 1) {
        std::string pass1 = getPassword("Enter password: ");
        std::string pass2 = getPassword("Confirm password: ");
        
        if (pass1 != pass2) {
            std::cerr << RED << "[-] Passwords do not match!" << RESET << std::endl;
            return 1;
        }
        
        if (pass1.empty()) {
            std::cerr << RED << "[-] Password cannot be empty!" << RESET << std::endl;
            return 1;
        }
        
        success = Crypto::encryptFile(inputFile, outputFile, pass1);
        
        // Затираем пароль из памяти
        pass1.clear();
        pass2.clear();
        
    } else if (mode == 2) {
        std::string password = getPassword("Enter password: ");
        success = Crypto::decryptFile(inputFile, outputFile, password);
        password.clear();
    }
    
    EVP_cleanup();
    
    return success ? 0 : 1;
}
