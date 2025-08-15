// server.cpp
#include "pqcrypto.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <iostream>
#include <thread>
#include <vector>
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

void handle_client(int client_fd) {
    try {
        const std::string kem = "Kyber512";
        const std::string sig = "Dilithium2";

        // 1) Generate Kyber and Dilithium keys (demo ephemeral)
        bytes kyber_pub, kyber_priv;
        bytes dilithium_pub, dilithium_priv;
        kem_generate_keypair(kem, kyber_pub, kyber_priv);
        sig_generate_keypair(sig, dilithium_pub, dilithium_priv);

        // 2) Make cert and send it
        bytes cert = make_cert_signed_by_dilithium(kyber_pub, dilithium_pub, dilithium_priv, sig);
        unsigned char lenb[4];
        write_u32_be((uint32_t)cert.size(), lenb);
        send_all(client_fd, lenb, 4);
        send_all(client_fd, cert.data(), cert.size());
        std::cout << "[server] sent cert (" << cert.size() << " bytes)\n";

        // 3) Receive encaps ciphertext length + ciphertext
        unsigned char clb[4];
        recv_all(client_fd, clb, 4);
        uint32_t ctlen = read_u32_be(clb);
        bytes ct(ctlen);
        recv_all(client_fd, ct.data(), ctlen);
        std::cout << "[server] received ct (" << ctlen << " bytes)\n";

        // 4) Decapsulate and derive AES key
        bytes shared;
        kem_decaps(kem, ct, kyber_priv, shared);

        unsigned char key[32];
        if (!hkdf_sha256(nullptr, 0, shared.data(), shared.size(), (const unsigned char*)"pqproto v1", 10, key, sizeof(key))) {
            throw std::runtime_error("HKDF failed");
        }
        secure_clear(shared);

        // 5) Receive iv len, iv, ciphertext len, ciphertext, tag len, tag
        recv_all(client_fd, clb, 4); uint32_t ivlen = read_u32_be(clb);
        bytes iv(ivlen); recv_all(client_fd, iv.data(), ivlen);

        recv_all(client_fd, clb, 4); uint32_t ct2len = read_u32_be(clb);
        bytes ciphertext(ct2len); recv_all(client_fd, ciphertext.data(), ct2len);

        recv_all(client_fd, clb, 4); uint32_t taglen = read_u32_be(clb);
        bytes tag(taglen); recv_all(client_fd, tag.data(), taglen);

        // 6) Decrypt AES-GCM
        bytes plaintext;
        if (!aes256_gcm_decrypt(key, sizeof(key), iv.data(), iv.size(), ciphertext.data(), ciphertext.size(), nullptr, 0, tag.data(), tag.size(), plaintext)) {
            std::cerr << "[server] AES-GCM decrypt failed or auth failed\n";
            close(client_fd);
            OPENSSL_cleanse(key, sizeof(key));
            return;
        }
        std::cout << "[server] got message: " << std::string(plaintext.begin(), plaintext.end()) << "\n";

        // 7) Reply: encrypt "Hello from server"
        AeadResult resp;
        if (!aes256_gcm_encrypt(key, sizeof(key), (const unsigned char*)"Hello from server", 17, nullptr, 0, resp)) {
            std::cerr << "[server] encrypt reply failed\n"; close(client_fd); OPENSSL_cleanse(key, sizeof(key)); return;
        }
        // send iv/ciphertext/tag
        write_u32_be((uint32_t)resp.iv.size(), clb); send_all(client_fd, clb, 4); send_all(client_fd, resp.iv.data(), resp.iv.size());
        write_u32_be((uint32_t)resp.ciphertext.size(), clb); send_all(client_fd, clb, 4); send_all(client_fd, resp.ciphertext.data(), resp.ciphertext.size());
        write_u32_be((uint32_t)resp.tag.size(), clb); send_all(client_fd, clb, 4); send_all(client_fd, resp.tag.data(), resp.tag.size());

        OPENSSL_cleanse(key, sizeof(key));
        secure_clear(kyber_priv);
        secure_clear(dilithium_priv);

        close(client_fd);
    } catch (const std::exception &ex) {
        std::cerr << "[server] exception: " << ex.what() << "\n";
        close(client_fd);
    }
}

int main() {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }
    int opt = 1; setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(5555);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 5) < 0) { perror("listen"); return 1; }

    std::cout << "[server] listening on 0.0.0.0:5555\n";

    while (true) {
        sockaddr_in cli; socklen_t clilen = sizeof(cli);
        int fd = accept(listen_fd, (sockaddr*)&cli, &clilen);
        if (fd < 0) { perror("accept"); continue; }
        std::cout << "[server] client connected: " << inet_ntoa(cli.sin_addr) << ":" << ntohs(cli.sin_port) << "\n";
        std::thread t(handle_client, fd);
        t.detach();
    }

    close(listen_fd);
    return 0;
}
