// client_pq.cpp
#include "pqcrypto.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>

using namespace PQCrypto;

static void send_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) throw std::runtime_error("socket send error");
        sent += n;
    }
}

static void recv_all(int fd, unsigned char *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(fd, buf + recvd, len - recvd, 0);
        if (n <= 0) throw std::runtime_error("socket recv error");
        recvd += n;
    }
}

// Frame: [u32 ivlen][iv][u32 ctlen][ct][u32 taglen][tag]
static void send_encrypted_frame(int fd, const unsigned char key[32], const bytes &plain) {
    AeadResult aead;
    if (!aes256_gcm_encrypt(key, plain.data(), plain.size(), nullptr, 0, aead)) {
        throw std::runtime_error("aes256_gcm_encrypt failed");
    }
    unsigned char u32[4];
    write_u32_be((uint32_t)aead.iv.size(), u32); send_all(fd, u32, 4); send_all(fd, aead.iv.data(), aead.iv.size());
    write_u32_be((uint32_t)aead.ciphertext.size(), u32); send_all(fd, u32, 4); send_all(fd, aead.ciphertext.data(), aead.ciphertext.size());
    write_u32_be((uint32_t)aead.tag.size(), u32); send_all(fd, u32, 4); send_all(fd, aead.tag.data(), aead.tag.size());
}

static bool recv_encrypted_frame(int fd, const unsigned char key[32], bytes &out_plain) {
    unsigned char u32[4];
    if (recv(fd, u32, 4, MSG_WAITALL) != 4) return false;
    uint32_t ivlen = read_u32_be(u32);
    if (!ivlen || ivlen > 64) return false;
    bytes iv(ivlen);
    recv_all(fd, iv.data(), iv.size());

    if (recv(fd, u32, 4, MSG_WAITALL) != 4) return false;
    uint32_t ctlen = read_u32_be(u32);
    if (ctlen > (64*1024*1024)) return false;
    bytes ct(ctlen);
    if (ctlen) recv_all(fd, ct.data(), ct.size());

    if (recv(fd, u32, 4, MSG_WAITALL) != 4) return false;
    uint32_t taglen = read_u32_be(u32);
    if (taglen != 16) return false;
    bytes tag(taglen);
    if (taglen) recv_all(fd, tag.data(), tag.size());

    return aes256_gcm_decrypt(key, iv.data(), iv.size(), ct.data(), ct.size(), nullptr, 0, tag.data(), tag.size(), out_plain);
}

static std::string show_menu() {
    std::cout << "\n----------------------------------------\n";
    std::cout << "Welcome to the Car Update Server!\n";
    std::cout << "1. Check for updates\n";
    std::cout << "2. Download updates\n";
    std::cout << "3. Install updates\n";
    std::cout << "4. Exit\n";
    std::cout << "Enter your choice: ";
    std::string choice;
    std::getline(std::cin, choice);
    return choice;
}

static void do_install() {
    std::cout << "[client] (placeholder) Installing update...\n";
    // Keep your existing local logic here if needed
}

int main() {
    try {
        // 1) Connect
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { perror("socket"); return 1; }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(5555);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr); // change as needed
        if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }

        const char *KEM_ALG = OQS_KEM_alg_kyber_768;
        const char *SIG_ALG = OQS_SIG_alg_dilithium_3;

        // 2) Receive server cert
        unsigned char u32[4];
        if (recv(fd, u32, 4, MSG_WAITALL) != 4) throw std::runtime_error("bad cert len");
        uint32_t certlen = read_u32_be(u32);
        bytes cert(certlen);
        recv_all(fd, cert.data(), cert.size());

        bytes kyber_pub, dilithium_pub, signature;
        parse_cert_blob(cert, kyber_pub, dilithium_pub, signature);
        // Self-signed check (non-authenticating): verify signature over (kyber_pub||dilithium_pub) with dilithium_pub
        bytes msg; msg.insert(msg.end(), kyber_pub.begin(), kyber_pub.end());
        msg.insert(msg.end(), dilithium_pub.begin(), dilithium_pub.end());
        if (!sig_verify(SIG_ALG, dilithium_pub, msg, signature)) {
            throw std::runtime_error("server certificate signature invalid");
        }
        std::cout << "[client] received server cert (" << cert.size() << " bytes)\n";

        // 3) Encapsulate to server Kyber pubkey, send ct
        bytes ct, shared;
        kem_encaps(KEM_ALG, kyber_pub, ct, shared);
        write_u32_be((uint32_t)ct.size(), u32);
        send_all(fd, u32, 4);
        send_all(fd, ct.data(), ct.size());

        // 4) Derive AES key
        unsigned char key[32];
        const unsigned char salt[] = "server-salt-v1";
        const unsigned char info[] = "pq-handshake v1";
        if (!hkdf_sha256(salt, sizeof(salt)-1, shared.data(), shared.size(), info, sizeof(info)-1, key, sizeof(key))) {
            throw std::runtime_error("hkdf failed");
        }
        secure_clear(shared);

        std::string curr_version = "1.0.0";
        std::string avlb_version = curr_version;

        while (true) {
            std::string choice = show_menu();
            if (choice == "1") {
                // check
                send_encrypted_frame(fd, key, bytes({'c','h','e','c','k'}));
                bytes resp;
                if (!recv_encrypted_frame(fd, key, resp)) throw std::runtime_error("no response");
                avlb_version.assign(resp.begin(), resp.end());
                std::cout << "Current version: " << curr_version << "\n";
                std::cout << "Available version: " << avlb_version << "\n";
            } else if (choice == "2") {
                // download update
                std::string cmd = "get " + avlb_version;
                send_encrypted_frame(fd, key, bytes(cmd.begin(), cmd.end()));

                bytes resp;
                if (!recv_encrypted_frame(fd, key, resp)) throw std::runtime_error("no response");
                std::string status(resp.begin(), resp.end());
                if (status != "OK") {
                    std::cout << "Server replied: " << status << "\n";
                    continue;
                }
                std::string filename = "car_update_" + avlb_version + ".exe";
                std::ofstream out(filename, std::ios::binary);
                if (!out) { std::cout << "Local file error\n"; continue; }

                std::cout << "Receiving " << filename << " ...\n";
                while (true) {
                    bytes chunk;
                    if (!recv_encrypted_frame(fd, key, chunk)) { std::cout << "Transfer aborted\n"; break; }
                    if (chunk.empty()) break; // EOF (server sends an authenticated empty frame)
                    out.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                    if (!out) { std::cout << "File write error\n"; break; }
                }
                out.close();
                std::cout << "File downloaded successfully\n";
            } else if (choice == "3") {
                do_install();
            } else if (choice == "4") {
                send_encrypted_frame(fd, key, bytes({'c','l','o','s','e'}));
                bytes resp;
                if (recv_encrypted_frame(fd, key, resp)) {
                    std::cout << std::string(resp.begin(), resp.end());
                }
                break;
            } else {
                // pass through unknown command for server message
                bytes any(choice.begin(), choice.end());
                send_encrypted_frame(fd, key, any);
                bytes resp;
                if (recv_encrypted_frame(fd, key, resp)) {
                    std::cout << std::string(resp.begin(), resp.end());
                }
            }
        }

        OPENSSL_cleanse(key, sizeof(key));
        close(fd);
    } catch (const std::exception &e) {
        std::cerr << "[client] error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
