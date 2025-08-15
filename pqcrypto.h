// pqcrypto.h
// Header-only API for a simple PQC handshake using liboqs (Kyber KEM + Dilithium SIG)
// Symmetric crypto: OpenSSL EVP (HKDF-SHA256 + AES-256-GCM)
//
// Build example (Linux):
//   g++ -std=c++17 server_pq.cpp -I. -loqs -lcrypto -lpthread -o server_pq
//   g++ -std=c++17 client_pq.cpp -I. -loqs -lcrypto -o client_pq
//
// NOTE: This sample uses a self-signed "certificate" containing the server's
// Kyber public key and Dilithium public key, plus a Dilithium signature over
// those bytes. Without a pre-shared/embedded server Dilithium public key on the
// client, this is not *authenticated* (TOFU at best). For production, pin or
// verify with a real PKI.

#ifndef PQCRYPTO_H
#define PQCRYPTO_H

#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <algorithm>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace PQCrypto {

using bytes = std::vector<unsigned char>;

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------
static inline void secure_clear(bytes &b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
    b.clear();
}

static inline void write_u32_be(uint32_t v, unsigned char out[4]) {
    out[0] = (v >> 24) & 0xFF;
    out[1] = (v >> 16) & 0xFF;
    out[2] = (v >>  8) & 0xFF;
    out[3] = (v      ) & 0xFF;
}

static inline uint32_t read_u32_be(const unsigned char in[4]) {
    return (uint32_t(in[0]) << 24) | (uint32_t(in[1]) << 16) |
           (uint32_t(in[2]) <<  8) | (uint32_t(in[3]));
}

// -----------------------------------------------------------------------------
// HKDF-SHA256 (pure OpenSSL EVP/HMAC, no deprecated API)
// -----------------------------------------------------------------------------
static inline bool hkdf_sha256(
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm,  size_t ikm_len,
    const unsigned char *info, size_t info_len,
    unsigned char *out,        size_t out_len)
{
    // Extract step
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len)) {
        return false;
    }

    // Expand step
    bytes t; t.reserve(EVP_MAX_MD_SIZE);
    unsigned char counter = 1;
    size_t produced = 0;
    while (produced < out_len) {
        // T(i) = HMAC(PRK, T(i-1) | info | counter)
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx) return false;
        if (1 != HMAC_Init_ex(ctx, prk, prk_len, EVP_sha256(), nullptr)) { HMAC_CTX_free(ctx); return false; }
        if (!t.empty()) { if (1 != HMAC_Update(ctx, t.data(), t.size())) { HMAC_CTX_free(ctx); return false; } }
        if (info && info_len) { if (1 != HMAC_Update(ctx, info, info_len)) { HMAC_CTX_free(ctx); return false; } }
        if (1 != HMAC_Update(ctx, &counter, 1)) { HMAC_CTX_free(ctx); return false; }
        unsigned int tlen = 0;
        t.resize(EVP_MAX_MD_SIZE);
        if (1 != HMAC_Final(ctx, t.data(), &tlen)) { HMAC_CTX_free(ctx); return false; }
        t.resize(tlen);
        HMAC_CTX_free(ctx);

        size_t take = std::min(t.size(), out_len - produced);
        std::memcpy(out + produced, t.data(), take);
        produced += take;
        counter++;
    }

    // cleanse PRK and temp
    OPENSSL_cleanse(prk, sizeof(prk));
    if (!t.empty()) OPENSSL_cleanse(t.data(), t.size());
    return true;
}

// -----------------------------------------------------------------------------
struct AeadResult {
    bytes iv;         // 12 bytes
    bytes ciphertext; // variable
    bytes tag;        // 16 bytes
};

static inline bool aes256_gcm_encrypt(
    const unsigned char key[32],
    const unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *aad, size_t aad_len,
    AeadResult &out)
{
    const size_t iv_len = 12;
    out.iv.resize(iv_len);
    if (1 != RAND_bytes(out.iv.data(), (int)iv_len)) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int ok = 1;
    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, nullptr);
    ok &= EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, out.iv.data());
    if (!ok) { EVP_CIPHER_CTX_free(ctx); return false; }

    int len = 0;
    if (aad && aad_len) {
        if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, (int)aad_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    out.ciphertext.resize(plaintext_len);
    int outl1 = 0;
    if (1 != EVP_EncryptUpdate(ctx, out.ciphertext.data(), &outl1, plaintext, (int)plaintext_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    int outl2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + outl1, &outl2)) { EVP_CIPHER_CTX_free(ctx); return false; }
    out.ciphertext.resize(outl1 + outl2);

    out.tag.resize(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)out.tag.size(), out.tag.data())) { EVP_CIPHER_CTX_free(ctx); return false; }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

static inline bool aes256_gcm_decrypt(
    const unsigned char key[32],
    const unsigned char *iv, size_t iv_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *tag, size_t tag_len,
    bytes &out_plain)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int ok = 1;
    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, nullptr);
    ok &= EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    if (!ok) { EVP_CIPHER_CTX_free(ctx); return false; }

    int len = 0;
    if (aad && aad_len) {
        if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aad_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    out_plain.resize(ciphertext_len);
    int outl1 = 0;
    if (ciphertext_len) {
        if (1 != EVP_DecryptUpdate(ctx, out_plain.data(), &outl1, ciphertext, (int)ciphertext_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, (void*)tag)) { EVP_CIPHER_CTX_free(ctx); return false; }

    int outl2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, out_plain.data() + outl1, &outl2)) { EVP_CIPHER_CTX_free(ctx); return false; }
    out_plain.resize(outl1 + outl2);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// -----------------------------------------------------------------------------
// liboqs helpers
// -----------------------------------------------------------------------------
static inline void kem_generate_keypair(const char *alg, bytes &pub, bytes &priv) {
    OQS_KEM *k = OQS_KEM_new(alg);
    if (!k) throw std::runtime_error("OQS_KEM_new failed");
    pub.resize(k->length_public_key);
    priv.resize(k->length_secret_key);
    if (OQS_KEM_keypair(k, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(k);
        throw std::runtime_error("OQS_KEM_keypair failed");
    }
    OQS_KEM_free(k);
}

static inline void kem_encaps(const char *alg, const bytes &peer_pub, bytes &ciphertext, bytes &shared) {
    OQS_KEM *k = OQS_KEM_new(alg);
    if (!k) throw std::runtime_error("OQS_KEM_new failed");
    ciphertext.resize(k->length_ciphertext);
    shared.resize(k->length_shared_secret);
    if (OQS_KEM_encaps(k, ciphertext.data(), shared.data(), peer_pub.data()) != OQS_SUCCESS) {
        OQS_KEM_free(k);
        throw std::runtime_error("OQS_KEM_encaps failed");
    }
    OQS_KEM_free(k);
}

static inline void kem_decaps(const char *alg, const bytes &ct, const bytes &priv, bytes &shared) {
    OQS_KEM *k = OQS_KEM_new(alg);
    if (!k) throw std::runtime_error("OQS_KEM_new failed");
    shared.resize(k->length_shared_secret);
    if (OQS_KEM_decaps(k, shared.data(), ct.data(), priv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(k);
        throw std::runtime_error("OQS_KEM_decaps failed");
    }
    OQS_KEM_free(k);
}

static inline void sig_generate_keypair(const char *alg, bytes &pub, bytes &priv) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) throw std::runtime_error("OQS_SIG_new failed");
    pub.resize(s->length_public_key);
    priv.resize(s->length_secret_key);
    if (OQS_SIG_keypair(s, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_SIG_free(s);
        throw std::runtime_error("OQS_SIG_keypair failed");
    }
    OQS_SIG_free(s);
}

static inline void sig_sign(const char *alg, const bytes &priv, const bytes &msg, bytes &sig) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) throw std::runtime_error("OQS_SIG_new failed");
    sig.resize(s->length_signature);
    size_t siglen = 0;
    if (OQS_SIG_sign(s, sig.data(), &siglen, msg.data(), msg.size(), priv.data()) != OQS_SUCCESS) {
        OQS_SIG_free(s);
        throw std::runtime_error("OQS_SIG_sign failed");
    }
    sig.resize(siglen);
    OQS_SIG_free(s);
}

static inline bool sig_verify(const char *alg, const bytes &pub, const bytes &msg, const bytes &sig) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return false;
    bool ok = (OQS_SIG_verify(s, msg.data(), msg.size(), sig.data(), sig.size(), pub.data()) == OQS_SUCCESS);
    OQS_SIG_free(s);
    return ok;
}

// -----------------------------------------------------------------------------
// "Certificate" (very simple blob):
//   [4B kyber_pub_len][kyber_pub]
//   [4B dilithium_pub_len][dilithium_pub]
//   [4B sig_len][sig over (kyber_pub||dilithium_pub)]
// -----------------------------------------------------------------------------
static inline bytes make_cert_signed_by_dilithium(const bytes &kyber_pub,
                                                  const bytes &dilithium_pub,
                                                  const bytes &dilithium_priv,
                                                  const char *sig_alg)
{
    bytes msg; msg.reserve(kyber_pub.size() + dilithium_pub.size());
    msg.insert(msg.end(), kyber_pub.begin(), kyber_pub.end());
    msg.insert(msg.end(), dilithium_pub.begin(), dilithium_pub.end());

    bytes signature;
    sig_sign(sig_alg, dilithium_priv, msg, signature);

    bytes cert;
    unsigned char u32[4];

    write_u32_be((uint32_t)kyber_pub.size(), u32); cert.insert(cert.end(), u32, u32+4);
    cert.insert(cert.end(), kyber_pub.begin(), kyber_pub.end());

    write_u32_be((uint32_t)dilithium_pub.size(), u32); cert.insert(cert.end(), u32, u32+4);
    cert.insert(cert.end(), dilithium_pub.begin(), dilithium_pub.end());

    write_u32_be((uint32_t)signature.size(), u32); cert.insert(cert.end(), u32, u32+4);
    cert.insert(cert.end(), signature.begin(), signature.end());

    return cert;
}

static inline void parse_cert_blob(const bytes &cert, bytes &kyber_pub, bytes &dilithium_pub, bytes &sig) {
    size_t pos = 0;
    if (cert.size() < 12) throw std::runtime_error("bad cert");

    uint32_t klen = read_u32_be(cert.data()+pos); pos += 4;
    if (pos + klen > cert.size()) throw std::runtime_error("bad cert klen");
    kyber_pub.assign(cert.begin()+pos, cert.begin()+pos+klen); pos += klen;

    uint32_t dlen = read_u32_be(cert.data()+pos); pos += 4;
    if (pos + dlen > cert.size()) throw std::runtime_error("bad cert dlen");
    dilithium_pub.assign(cert.begin()+pos, cert.begin()+pos+dlen); pos += dlen;

    uint32_t slen = read_u32_be(cert.data()+pos); pos += 4;
    if (pos + slen > cert.size()) throw std::runtime_error("bad cert slen");
    sig.assign(cert.begin()+pos, cert.begin()+pos+slen);
}

// -----------------------------------------------------------------------------
} // namespace PQCrypto

#endif // PQCRYPTO_H
