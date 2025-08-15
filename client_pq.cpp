// client.cpp
#include "pqcrypto.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
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

int main() {
    try {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { perror("socket"); return 1; }

        sockaddr_in srv;
        srv.sin_family = AF_INET;
        srv.sin_port = htons(5555);
        inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);

        if (connect(fd, (sockaddr*)&srv, sizeof(srv)) < 0) { perror("connect"); return 1; }
        std::cout << "[client] connected to server\n";

        // 1) Receive cert length + cert blob
        unsigned char lenb[4];
        recv_all(fd, lenb, 4);
        uint32_t certlen = read_u32_be(lenb);
        bytes cert(certlen);
        recv_all(fd, cert.data(), certlen);
        std::cout << "[client] received cert (" << certlen << " bytes)\n";

        // 2) parse cert to kyber_pub, dilithium_pub, sig and verify
        bytes kyber_pub, dilithium_pub, sig;
        parse_cert_blob(cert, kyber_pub, dilithium_pub, sig);
        const std::string sigalg = "Dilithium2";
        if (!sig_verify(sigalg, dilithium_pub, kyber_pub.data(), kyber_pub.size(), sig.data(), sig.size())) {
            throw std::runtime_error("signature verification failed");
        }
        std::cout << "[client] cert verified\n";

        // 3) Encapsulate to server kyber pub -> produce ct & shared
        const std::string kem = "Kyber512";
        bytes ct, shared;
        kem_encaps(kem, kyber_pub, ct, shared);

        // send ct length + ct
        write_u32_be((uint32_t)ct.size(), lenb);
        send_all(fd, lenb, 4);
        send_all(fd, ct.data(), ct.size());
        std::cout << "[client] sent ct (" << ct.size() << " bytes)\n";

        // derive AES-256 key (HKDF)
        unsigned char key[32];
        if (!hkdf_sha256(nullptr, 0, shared.data(), shared.size(), (const unsigned char*)"pqproto v1", 10, key, sizeof(key))) {
            throw std::runtime_error("HKDF failed");
        }
        secure_clear(shared);

        // 4) Encrypt an application message with AES-GCM
        const std::string msg = "Hello from client";
        AeadResult res;
        if (!aes256_gcm_encrypt(key, sizeof(key), (const unsigned char*)msg.data(), msg.size(), nullptr, 0, res)) {
            throw std::runtime_error("AES-GCM encrypt failed");
        }

        // send iv len + iv, ciphertext len + ciphertext, tag len + tag
        write_u32_be((uint32_t)res.iv.size(), lenb); send_all(fd, lenb, 4); send_all(fd, res.iv.data(), res.iv.size());
        write_u32_be((uint32_t)res.ciphertext.size(), lenb); send_all(fd, lenb, 4); send_all(fd, res.ciphertext.data(), res.ciphertext.size());
        write_u32_be((uint32_t)res.tag.size(), lenb); send_all(fd, lenb, 4); send_all(fd, res.tag.data(), res.tag.size());
        std::cout << "[client] sent encrypted message\n";

        // receive server response (iv/ciphertext/tag)
        recv_all(fd, lenb, 4); uint32_t ivlen = read_u32_be(lenb);
        bytes iv(ivlen); recv_all(fd, iv.data(), ivlen);

        recv_all(fd, lenb, 4); uint32_t ctlen = read_u32_be(lenb);
        bytes ciphertext(ctlen); recv_all(fd, ciphertext.data(), ctlen);

        recv_all(fd, lenb, 4); uint32_t taglen = read_u32_be(lenb);
        bytes tag(taglen); recv_all(fd, tag.data(), taglen);

        bytes plaintext;
        if (!aes256_gcm_decrypt(key, sizeof(key), iv.data(), iv.size(), ciphertext.data(), ciphertext.size(), nullptr, 0, tag.data(), tag.size(), plaintext)) {
            std::cerr << "[client] decrypt failed or auth failed\n";
        } else {
            std::cout << "[client] server replied: " << std::string(plaintext.begin(), plaintext.end()) << "\n";
        }

        OPENSSL_cleanse(key, sizeof(key));
        close(fd);
    } catch (const std::exception &ex) {
        std::cerr << "[client] exception: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
