"""
mceliece_crypto.py - Classic McEliece KEM + SPHINCS+ signatures
Uses pyoqs (liboqs) for PQC and cryptography for AES-GCM
"""

import struct, os, time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oqs

class PQCrypto:
    def write_u32_be(value): return struct.pack('>I', value)
    def read_u32_be(data): return struct.unpack('>I', data)[0]

    def secure_clear(data):
        if data:
            try:
                for i in range(len(data)): data[i] = 0
            except Exception:
                pass

    def hkdf_sha256(ikm, salt, info, length):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length,
                    salt=salt, info=info, backend=default_backend())
        return hkdf.derive(ikm)

    def aes256_gcm_encrypt(key, plaintext, aad=None):
        iv = os.urandom(12)
        enc = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        if aad: enc.authenticate_additional_data(aad)
        ciphertext = enc.update(plaintext) + enc.finalize()
        return iv, ciphertext, enc.tag

    def aes256_gcm_decrypt(key, iv, ciphertext, tag, aad=None):
        dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        if aad: dec.authenticate_additional_data(aad)
        return dec.update(ciphertext) + dec.finalize()

class KEMManager:
    def __init__(self, algorithm="Classic-McEliece-348864"):
        self.algorithm = algorithm
        self.kem = None
        self.public_key = None
        self.secret_key = None

    def generate_keypair(self):
        self.kem = oqs.KeyEncapsulation(self.algorithm)
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()
        return self.public_key, self

    def encapsulate(algorithm, public_key):
        kem = oqs.KeyEncapsulation(algorithm)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext):
        if not self.kem:
            raise RuntimeError("No KEM instance available for decapsulation")
        return self.kem.decap_secret(ciphertext)

class SignatureManager:
    def __init__(self, algorithm="SPHINCS+-SHA2-128s-simple"):
        self.algorithm = algorithm
        self.sig = None
        self.public_key = None
        self.secret_key = None

    def generate_keypair(self):
        self.sig = oqs.Signature(self.algorithm)
        self.public_key = self.sig.generate_keypair()
        self.secret_key = self.sig.export_secret_key()
        return self.public_key, self

    def sign(self, message):
        if not self.sig:
            raise RuntimeError("No signature instance available for signing")
        return self.sig.sign(message)

    def verify(algorithm, message, signature, public_key):
        try:
            v = oqs.Signature(algorithm)
            return v.verify(message, signature, public_key)
        except Exception:
            return False

class Certificate:
    """
    Simple self-signed bundle:
      [kem_pub_len][kem_pub][sig_pub_len][sig_pub][sig_len][signature(sig_pub || kem_pub)]
    """
    def create_cert(kem_pub, sig_pub, sig_manager):
        message = kem_pub + sig_pub
        signature = sig_manager.sign(message)

        blob = b""
        blob += PQCrypto.write_u32_be(len(kem_pub)) + kem_pub
        blob += PQCrypto.write_u32_be(len(sig_pub)) + sig_pub
        blob += PQCrypto.write_u32_be(len(signature)) + signature
        return blob

    def parse_cert(cert):
        pos = 0
        kem_len = PQCrypto.read_u32_be(cert[pos:pos+4]); pos += 4
        kem_pub = cert[pos:pos+kem_len]; pos += kem_len
        sp_len = PQCrypto.read_u32_be(cert[pos:pos+4]); pos += 4
        sig_pub = cert[pos:pos+sp_len]; pos += sp_len
        sig_len = PQCrypto.read_u32_be(cert[pos:pos+4]); pos += 4
        signature = cert[pos:pos+sig_len]
        return kem_pub, sig_pub, signature

class SecureFrame:
    def send_all(sock, data):
        total = 0
        while total < len(data):
            sent = sock.send(data[total:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total += sent

    def recv_all(sock, length):
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise RuntimeError("Socket connection broken")
            data += chunk
        return data

    def send_encrypted_frame(sock, key, plaintext):
        start = time.time()
        iv, ct, tag = PQCrypto.aes256_gcm_encrypt(key, plaintext)
        elapsed = time.time() - start

        sock.send(PQCrypto.write_u32_be(len(iv)));     SecureFrame.send_all(sock, iv)
        sock.send(PQCrypto.write_u32_be(len(ct)));     SecureFrame.send_all(sock, ct)
        sock.send(PQCrypto.write_u32_be(len(tag)));    SecureFrame.send_all(sock, tag)
        return elapsed

    def recv_encrypted_frame(sock, key):
        try:
            iv_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock, 4))
            if iv_len == 0 or iv_len > 64: raise ValueError("Invalid IV length")
            iv = SecureFrame.recv_all(sock, iv_len)

            ct_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock, 4))
            if ct_len > 64*1024*1024: raise ValueError("Ciphertext too large")
            ct = SecureFrame.recv_all(sock, ct_len) if ct_len > 0 else b""

            tag_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock, 4))
            if tag_len != 16: raise ValueError("Invalid GCM tag length")
            tag = SecureFrame.recv_all(sock, tag_len)

            start = time.time()
            pt = PQCrypto.aes256_gcm_decrypt(key, iv, ct, tag)
            dec_t = time.time() - start
            return pt, dec_t
        except Exception as e:
            print(f"Frame receive error: {e}")
            return None, 0.0
