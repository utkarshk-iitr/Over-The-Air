// server_pq.cpp
#include "pqcrypto.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <thread>
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
    if (!ctlen || ctlen > (64*1024*1024)) return false;
    bytes ct(ctlen);
    recv_all(fd, ct.data(), ct.size());

    if (recv(fd, u32, 4, MSG_WAITALL) != 4) return false;
    uint32_t taglen = read_u32_be(u32);
    if (taglen != 16) return false;
    bytes tag(taglen);
    recv_all(fd, tag.data(), tag.size());

    return aes256_gcm_decrypt(key, iv.data(), iv.size(), ct.data(), ct.size(), nullptr, 0, tag.data(), tag.size(), out_plain);
}

static void handle_client(int client_fd) {
    try {
        const char *KEM_ALG = OQS_KEM_alg_kyber_768;
        const char *SIG_ALG = OQS_SIG_alg_dilithium_3;

        // 1) Generate server keys
        bytes kyber_pub, kyber_priv;
        bytes dilithium_pub, dilithium_priv;
        kem_generate_keypair(KEM_ALG, kyber_pub, kyber_priv);
        sig_generate_keypair(SIG_ALG, dilithium_pub, dilithium_priv);

        // 2) Cert -> client
        bytes cert = make_cert_signed_by_dilithium(kyber_pub, dilithium_pub, dilithium_priv, SIG_ALG);
        unsigned char u32[4];
        write_u32_be((uint32_t)cert.size(), u32);
        send_all(client_fd, u32, 4);
        send_all(client_fd, cert.data(), cert.size());

        // 3) Receive KEM ciphertext, decapsulate
        if (recv(client_fd, u32, 4, MSG_WAITALL) != 4) throw std::runtime_error("bad ct len");
        uint32_t ctlen = read_u32_be(u32);
        bytes ct(ctlen);
        recv_all(client_fd, ct.data(), ct.size());
        bytes shared;
        kem_decaps(KEM_ALG, ct, kyber_priv, shared);

        // 4) Derive AES key
        unsigned char key[32];
        const unsigned char salt[] = "server-salt-v1";
        const unsigned char info[] = "pq-handshake v1";
        if (!hkdf_sha256(salt, sizeof(salt)-1, shared.data(), shared.size(), info, sizeof(info)-1, key, sizeof(key))) {
            throw std::runtime_error("hkdf failed");
        }
        secure_clear(shared);

        // 5) Command loop over encrypted frames
        while (true) {
            bytes plain;
            if (!recv_encrypted_frame(client_fd, key, plain)) break;
            std::string cmd(reinterpret_cast<char*>(plain.data()), plain.size());

            if (cmd == "close") {
                std::string bye = "Closing connection...\n";
                send_encrypted_frame(client_fd, key, bytes(bye.begin(), bye.end()));
                break;
            } else if (cmd == "check") {
                std::string ver = "1.0.0"; // server version
                send_encrypted_frame(client_fd, key, bytes(ver.begin(), ver.end()));
            } else if (cmd.rfind("get ", 0) == 0) {
                std::string version = cmd.substr(4);
                std::string filename = "update_" + version + ".exe";
                std::ifstream in(filename, std::ios::binary);
                if (!in) {
                    std::string no = "NO";
                    send_encrypted_frame(client_fd, key, bytes(no.begin(), no.end()));
                    continue;
                } else {
                    std::string ok = "OK";
                    send_encrypted_frame(client_fd, key, bytes(ok.begin(), ok.end()));
                }
                // stream file in encrypted frames (each frame = raw chunk)
                const size_t CHUNK = 4096;
                bytes chunk;
                chunk.resize(CHUNK);
                while (in) {
                    in.read(reinterpret_cast<char*>(chunk.data()), CHUNK);
                    std::streamsize got = in.gcount();
                    if (got <= 0) break;
                    bytes payload(chunk.begin(), chunk.begin()+got);
                    send_encrypted_frame(client_fd, key, payload);
                }
                // send zero-length marker (still authenticated/tagged)
                send_encrypted_frame(client_fd, key, bytes{});
            } else {
                std::string msg = "Invalid command\n";
                send_encrypted_frame(client_fd, key, bytes(msg.begin(), msg.end()));
            }
        }

        OPENSSL_cleanse(key, sizeof(key));
        close(client_fd);
    } catch (const std::exception &e) {
        std::cerr << "[server] error: " << e.what() << std::endl;
        close(client_fd);
    }
}

int main() {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(5555);
    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 16) < 0) { perror("listen"); return 1; }

    std::cout << "[server] listening on 0.0.0.0:5555\n";
    while (true) {
        sockaddr_in cli{}; socklen_t cl = sizeof(cli);
        int fd = accept(listen_fd, (sockaddr*)&cli, &cl);
        if (fd < 0) { perror("accept"); continue; }
        std::cout << "[server] client connected: " << inet_ntoa(cli.sin_addr) << ":" << ntohs(cli.sin_port) << std::endl;
        std::thread(handle_client, fd).detach();
    }
    return 0;
}
