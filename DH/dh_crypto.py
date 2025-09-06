"""
dh_crypto.py - Diffie-Hellman key exchange with AES-GCM for secure communication
Uses cryptography library for DH key exchange and AES-256-GCM for symmetric encryption
Simplified version without ZKP authentication
"""

import struct
import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

    def hkdf_sha256(ikm, salt, info, length):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info, backend=default_backend())
        return hkdf.derive(ikm)

    def aes256_gcm_encrypt(key, plaintext, aad=None):
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        if aad: 
            encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    def aes256_gcm_decrypt(key, iv, ciphertext, tag, aad=None):
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        if aad: 
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

class DHKeyManager:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key_bytes = None
        self.parameters = None
        # Use pre-generated safe parameters to avoid expensive generation
        self._init_parameters()

    def _init_parameters(self):
        # Use RFC 3526 Group 14 (2048-bit MODP Group) for stability
        # This avoids the expensive parameter generation that can cause segfaults
        p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
        g = 2
        
        # Create DH parameters from the standard values
        from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers, DHParameters
        param_numbers = DHParameterNumbers(p, g)
        self.parameters = param_numbers.parameters(backend=default_backend())

    def generate_keypair(self):
        # Generate private key using pre-initialized parameters
        self.private_key = self.parameters.generate_private_key()
        
        # Get public key in PEM format
        pub_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_bytes = pub_pem
        
        # Get parameters in PEM format for sharing
        params_pem = self.parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        
        return pub_pem, params_pem, self

    def compute_shared_secret(self, peer_public_key_bytes):
        if not self.private_key:
            raise RuntimeError("No DH private key available for shared secret computation")
        
        # Load peer's public key
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        
        # Compute shared secret
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret

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

    def send_encrypted_frame(sock, key, plaintext):
        start = time.time()
        iv, ciphertext, tag = PQCrypto.aes256_gcm_encrypt(key, plaintext)
        end = time.time()

        sock.send(PQCrypto.write_u32_be(len(iv)))
        SecureFrame.send_all(sock, iv)
        
        sock.send(PQCrypto.write_u32_be(len(ciphertext)))
        SecureFrame.send_all(sock, ciphertext)

        sock.send(PQCrypto.write_u32_be(len(tag)))
        SecureFrame.send_all(sock, tag)
        return end - start

    def recv_encrypted_frame(sock, key):
        try:
            iv_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock, 4))
            if iv_len == 0 or iv_len > 64:
                raise ValueError("Invalid IV length")
            iv = SecureFrame.recv_all(sock, iv_len)

            ct_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock, 4))
            if ct_len > 64*1024*1024:
                raise ValueError("Ciphertext too large")
            ciphertext = SecureFrame.recv_all(sock, ct_len) if ct_len > 0 else b''
            
            tag_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock, 4))
            if tag_len != 16:
                raise ValueError("Invalid tag length")
            tag = SecureFrame.recv_all(sock, tag_len)
            
            start = time.time()
            pt = PQCrypto.aes256_gcm_decrypt(key, iv, ciphertext, tag)
            end = time.time()
            return pt, end - start

        except Exception as e:
            print(f"Frame receive error: {e}")
            return None, 0
