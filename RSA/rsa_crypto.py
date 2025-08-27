"""
pqcrypto.py - RSA-only crypto helpers and framed RSA transport (no AES)
Uses cryptography library (RSA OAEP for encryption, PSS for signatures).
"""

import struct
import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class PQCrypto:
    def write_u32_be(value):
        return struct.pack('>I', value)

    def read_u32_be(data):
        return struct.unpack('>I', data)[0]

    def secure_clear(data):
        if data:
            try:
                for i in range(len(data)):
                    data[i] = 0
            except Exception:
                pass

class RSAKeyManager:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key_bytes = None

    def generate_keypair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size, backend=default_backend()
        )
        pub_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_bytes = pub_pem
        return pub_pem, self

    def decrypt(self, ciphertext):
        if not self.private_key:
            raise RuntimeError("No RSA private key available for decryption")
        plaintext = self.private_key.decrypt(ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        return plaintext

    def sign(self, message):
        if not self.private_key:
            raise RuntimeError("No RSA private key available for signing")
        signature = self.private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def encrypt(public_key_bytes, plaintext):
        pub = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
        ciphertext = pub.encrypt(
            plaintext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        return ciphertext

    def verify(public_key_bytes, message, signature):
        try:
            pub = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
            pub.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def rsa_max_plain_len(public_key_bytes):
        pub = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
        key_size_bits = pub.key_size
        key_size_bytes = (key_size_bits + 7) // 8
        hash_len = 32  # SHA256
        return key_size_bytes - 2 * hash_len - 2


class Certificate:
    def create_cert(rsa_pub, rsa_manager):
        message = rsa_pub
        signature = rsa_manager.sign(message)
        cert = b''
        cert += PQCrypto.write_u32_be(len(rsa_pub))
        cert += rsa_pub
        cert += PQCrypto.write_u32_be(len(signature))
        cert += signature
        return cert

    def parse_cert(cert):
        pos = 0
        rsa_len = PQCrypto.read_u32_be(cert[pos:pos + 4])
        pos += 4
        rsa_pub = cert[pos:pos + rsa_len]
        pos += rsa_len
        sig_len = PQCrypto.read_u32_be(cert[pos:pos + 4])
        pos += 4
        signature = cert[pos:pos + sig_len]
        return rsa_pub, signature


class SecureFrame:
    def send_all(sock, data):
        total_sent = 0
        while total_sent < len(data):
            sent = sock.send(data[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent

    def recv_all(sock, length):
        data = b''
        while len(data) < length:
            packet = sock.recv(length - len(data))
            if not packet:
                raise RuntimeError("Socket connection broken")
            data += packet
        return data

    def send_encrypted_frame(sock, recipient_pub_bytes, plaintext):

        if plaintext is None:
            plaintext = b''

        max_plain = RSAKeyManager.rsa_max_plain_len(recipient_pub_bytes)
        if max_plain <= 0:
            raise ValueError("Recipient RSA key too small or unsupported")

        chunks = [plaintext[i:i + max_plain] for i in range(0, len(plaintext), max_plain)] if len(plaintext) > 0 else []
        chunk_count = len(chunks)
        sock.send(PQCrypto.write_u32_be(chunk_count))

        ans = 0
        for ch in chunks:
            start = time.time()
            cipher = RSAKeyManager.encrypt(recipient_pub_bytes, ch)
            ans += time.time() - start
            sock.send(PQCrypto.write_u32_be(len(cipher)))
            SecureFrame.send_all(sock, cipher)

        return ans

    def recv_encrypted_frame(sock, rsa_manager):
        raw = SecureFrame.recv_all(sock, 4)
        chunk_count = PQCrypto.read_u32_be(raw)

        if chunk_count == 0:
            return b''

        parts = []
        ans = 0
        for _ in range(chunk_count):
            clen_raw = SecureFrame.recv_all(sock, 4)
            clen = PQCrypto.read_u32_be(clen_raw)
            if clen <= 0 or clen > 256 * 8:  # sanity cap
                raise ValueError("Invalid RSA chunk length")
            cipher = SecureFrame.recv_all(sock, clen)
            start = time.time()
            plain = rsa_manager.decrypt(cipher)
            ans += time.time() - start
            parts.append(plain)
        return (b''.join(parts), ans)
