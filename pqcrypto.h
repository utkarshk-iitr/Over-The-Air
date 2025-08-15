// pqcrypto.h
// Header-only API: liboqs (Kyber KEM + Dilithium SIG) + OpenSSL (HKDF via HMAC + AES-GCM)
// Compile example:
// g++ -std=c++17 server.cpp -I. -loqs -lcrypto -pthread -o server
// g++ -std=c++17 client.cpp -I. -loqs -lcrypto -pthread -o client

#ifndef PQCRYPTO_H
#define PQCRYPTO_H

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <iostream>

namespace PQCrypto {

using bytes = std::vector<unsigned char>;

// ---------------- utilities ----------------
static inline void secure_clear(bytes &b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
    b.clear();
}

static inline void write_u32_be(uint32_t v, unsigned char *out) {
    out[0] = (v >> 24) & 0xFF;
    out[1] = (v >> 16) & 0xFF;
    out[2] = (v >>  8) & 0xFF;
    out[3] = (v      ) & 0xFF;
}
static inline uint32_t read_u32_be(const unsigned char *in) {
    return (uint32_t(in[0])<<24) | (uint32_t(in[1])<<16) | (uint32_t(in[2])<<8) | uint32_t(in[3]);
}

// ---------------- HKDF-SHA256 (extract + expand using HMAC) ----------------
// Portable implementation: uses HMAC(EVP_sha256()) for Extract and HMAC_CTX_* loop for Expand.
// The HMAC_CTX_* family is deprecated on some OpenSSL versions; we suppress the deprecation warning
// so compilation is quiet on OpenSSL 3.x while keeping functionality portable.
static inline bool hkdf_sha256(
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len,
    const unsigned char *info, size_t info_len,
    unsigned char *out, size_t out_len)
{
    // HKDF-Extract: PRK = HMAC(salt, IKM)
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len)) {
        return false;
    }

    // HKDF-Expand: T(0) = empty, T(1) = HMAC(PRK, T(0) | info | 0x01), ...
    const unsigned int hash_len = SHA256_DIGEST_LENGTH;
    unsigned int n = (out_len + hash_len - 1) / hash_len;
    if (n > 255) return false; // per RFC5869 limitation

    unsigned char t[EVP_MAX_MD_SIZE];
    size_t t_len = 0;
    size_t generated = 0;

    // Suppress deprecated-declarations warnings around HMAC_CTX_new / HMAC_* if using newer OpenSSL
    #if defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif

    for (unsigned int i = 1; i <= n; ++i) {
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) {
            #if defined(__GNUC__)
            #pragma GCC diagnostic pop
            #endif
            OPENSSL_cleanse(prk, sizeof(prk));
            return false;
        }
        if (1 != HMAC_Init_ex(hctx, prk, (int)prk_len, EVP_sha256(), nullptr)) {
            HMAC_CTX_free(hctx);
            #if defined(__GNUC__)
            #pragma GCC diagnostic pop
            #endif
            OPENSSL_cleanse(prk, sizeof(prk));
            return false;
        }
        if (t_len) {
            if (1 != HMAC_Update(hctx, t, (int)t_len)) { HMAC_CTX_free(hctx); OPENSSL_cleanse(prk, sizeof(prk)); return false; }
        }
        if (info && info_len) {
            if (1 != HMAC_Update(hctx, info, (int)info_len)) { HMAC_CTX_free(hctx); OPENSSL_cleanse(prk, sizeof(prk)); return false; }
        }
        unsigned char c = (unsigned char)i;
        if (1 != HMAC_Update(hctx, &c, 1)) { HMAC_CTX_free(hctx); OPENSSL_cleanse(prk, sizeof(prk)); return false; }
        unsigned int outl = 0;
        if (1 != HMAC_Final(hctx, t, &outl)) { HMAC_CTX_free(hctx); OPENSSL_cleanse(prk, sizeof(prk)); return false; }
        HMAC_CTX_free(hctx);

        t_len = outl;
        size_t take = std::min<size_t>(t_len, out_len - generated);
        memcpy(out + generated, t, take);
        generated += take;
    }

    #if defined(__GNUC__)
    #pragma GCC diagnostic pop
    #endif

    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(t, sizeof(t));
    return true;
}

// ---------------- AES-256-GCM AEAD (EVP) ----------------
struct AeadResult {
    bytes iv;         // 12 bytes
    bytes ciphertext; // ciphertext
    bytes tag;        // 16 bytes tag
};

// Encrypt: key must be 32 bytes
static inline bool aes256_gcm_encrypt(
    const unsigned char *key32, size_t key_len,
    const unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *aad, size_t aad_len,
    AeadResult &out)
{
    if (key_len != 32) return false;
    const int iv_len = 12;
    out.iv.assign(iv_len, 0);
    if (1 != RAND_bytes(out.iv.data(), iv_len)) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32, out.iv.data())) { EVP_CIPHER_CTX_free(ctx); return false; }

    int len = 0;
    if (aad && aad_len) {
        if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, (int)aad_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    out.ciphertext.resize(plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int outl1 = 0;
    if (1 != EVP_EncryptUpdate(ctx, out.ciphertext.data(), &outl1, plaintext, (int)plaintext_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    int outl2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, out.ciphertext.data()+outl1, &outl2)) { EVP_CIPHER_CTX_free(ctx); return false; }
    out.ciphertext.resize(outl1 + outl2);

    out.tag.assign(16, 0);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)out.tag.size(), out.tag.data())) { EVP_CIPHER_CTX_free(ctx); return false; }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Decrypt: key must be 32 bytes; tag_len should be 16
static inline bool aes256_gcm_decrypt(
    const unsigned char *key32, size_t key_len,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *tag, size_t tag_len,
    bytes &out_plaintext)
{
    if (key_len != 32) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }

    int len = 0;
    if (aad && aad_len) {
        if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aad_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    out_plaintext.assign(ciphertext_len, 0);
    int plen1 = 0;
    if (1 != EVP_DecryptUpdate(ctx, out_plaintext.data(), &plen1, ciphertext, (int)ciphertext_len)) { EVP_CIPHER_CTX_free(ctx); return false; }

    // set expected tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, (void*)tag)) { EVP_CIPHER_CTX_free(ctx); return false; }

    int plen2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, out_plaintext.data()+plen1, &plen2)) { EVP_CIPHER_CTX_free(ctx); return false; }
    out_plaintext.resize(plen1 + plen2);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// ---------------- liboqs wrappers ----------------
// KEM
static inline void kem_generate_keypair(const std::string &kem_name, bytes &pub, bytes &priv) {
    OQS_KEM *kem = OQS_KEM_new(kem_name.c_str());
    if (!kem) throw std::runtime_error("OQS_KEM_new failed");
    pub.resize(kem->length_public_key);
    priv.resize(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("OQS_KEM_keypair failed");
    }
    OQS_KEM_free(kem);
}

static inline void kem_encaps(const std::string &kem_name, const bytes &peer_pub, bytes &ct, bytes &shared_secret) {
    OQS_KEM *kem = OQS_KEM_new(kem_name.c_str());
    if (!kem) throw std::runtime_error("OQS_KEM_new failed");
    ct.resize(kem->length_ciphertext);
    shared_secret.resize(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, ct.data(), shared_secret.data(), peer_pub.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("OQS_KEM_encaps failed");
    }
    OQS_KEM_free(kem);
}

static inline void kem_decaps(const std::string &kem_name, const bytes &ct, const bytes &priv, bytes &shared_secret) {
    OQS_KEM *kem = OQS_KEM_new(kem_name.c_str());
    if (!kem) throw std::runtime_error("OQS_KEM_new failed");
    shared_secret.resize(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, shared_secret.data(), ct.data(), priv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("OQS_KEM_decaps failed");
    }
    OQS_KEM_free(kem);
}

// Signatures (Dilithium)
static inline void sig_generate_keypair(const std::string &sig_name, bytes &pub, bytes &priv) {
    OQS_SIG *sig = OQS_SIG_new(sig_name.c_str());
    if (!sig) throw std::runtime_error("OQS_SIG_new failed");
    pub.resize(sig->length_public_key);
    priv.resize(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        throw std::runtime_error("OQS_SIG_keypair failed");
    }
    OQS_SIG_free(sig);
}

static inline void sig_sign(const std::string &sig_name, const bytes &priv, const unsigned char *msg, size_t msglen, bytes &sig_out) {
    OQS_SIG *sig = OQS_SIG_new(sig_name.c_str());
    if (!sig) throw std::runtime_error("OQS_SIG_new failed");
    sig_out.resize(sig->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, sig_out.data(), &sig_len, msg, msglen, priv.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        throw std::runtime_error("OQS_SIG_sign failed");
    }
    sig_out.resize(sig_len);
    OQS_SIG_free(sig);
}

static inline bool sig_verify(const std::string &sig_name, const bytes &pub, const unsigned char *msg, size_t msglen, const unsigned char *sigbuf, size_t siglen) {
    OQS_SIG *sig = OQS_SIG_new(sig_name.c_str());
    if (!sig) throw std::runtime_error("OQS_SIG_new failed");
    bool ok = (OQS_SIG_verify(sig, msg, msglen, sigbuf, siglen, pub.data()) == OQS_SUCCESS);
    OQS_SIG_free(sig);
    return ok;
}

// ---------------- cert helpers ----------------
// Simple demo cert format:
// [u32 kyber_pub_len][kyber_pub]
// [u32 dilithium_pub_len][dilithium_pub]
// [u32 sig_len][signature]   (signature computed over kyber_pub)
static inline bytes make_cert_signed_by_dilithium(const bytes &kyber_pub, const bytes &dilithium_pub, const bytes &dilithium_priv, const std::string &sig_alg) {
    bytes sig;
    sig_sign(sig_alg, dilithium_priv, kyber_pub.data(), kyber_pub.size(), sig);

    bytes out;
    unsigned char lenb[4];
    write_u32_be((uint32_t)kyber_pub.size(), lenb); out.insert(out.end(), lenb, lenb+4);
    out.insert(out.end(), kyber_pub.begin(), kyber_pub.end());

    write_u32_be((uint32_t)dilithium_pub.size(), lenb); out.insert(out.end(), lenb, lenb+4);
    out.insert(out.end(), dilithium_pub.begin(), dilithium_pub.end());

    write_u32_be((uint32_t)sig.size(), lenb); out.insert(out.end(), lenb, lenb+4);
    out.insert(out.end(), sig.begin(), sig.end());

    return out;
}

static inline void parse_cert_blob(const bytes &cert, bytes &kyber_pub, bytes &dilithium_pub, bytes &sig) {
    size_t pos = 0;
    if (cert.size() < 12) throw std::runtime_error("cert too small");
    uint32_t klen = read_u32_be(cert.data()+pos); pos += 4;
    if (pos + klen > cert.size()) throw std::runtime_error("bad cert klen");
    kyber_pub.assign(cert.begin()+pos, cert.begin()+pos+klen); pos += klen;

    uint32_t dlen = read_u32_be(cert.data()+pos); pos += 4;
    if (pos + dlen > cert.size()) throw std::runtime_error("bad cert dlen");
    dilithium_pub.assign(cert.begin()+pos, cert.begin()+pos+dlen); pos += dlen;

    uint32_t slen = read_u32_be(cert.data()+pos); pos += 4;
    if (pos + slen > cert.size()) throw std::runtime_error("bad cert slen");
    sig.assign(cert.begin()+pos, cert.begin()+pos+slen); pos += slen;
}

} // namespace PQCrypto

#endif // PQCRYPTO_H
