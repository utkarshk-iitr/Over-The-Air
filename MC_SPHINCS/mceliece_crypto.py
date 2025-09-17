"""
pqcrypto.py - Post-Quantum Cryptography utilities for Python
Uses pyoqs for PQC algorithms and cryptography library for symmetric crypto

Changed to use Classic McEliece KEM and SPHINCS+ signatures by default.
Be aware: Classic McEliece public keys and SPHINCS+ signatures are large.
"""

import struct
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oqs,time

class PQCrypto:
    def write_u32_be(value):
        return struct.pack('>I',value)

    def read_u32_be(data):
        return struct.unpack('>I',data)[0]

    def secure_clear(data):
        if data:
            for i in range(len(data)):
                data[i] = 0
    
    def hkdf_sha256(ikm,salt,info,length):
        hkdf = HKDF(algorithm=hashes.SHA256(),length=length,salt=salt,info=info,backend=default_backend())
        return hkdf.derive(ikm)

    def aes256_gcm_encrypt(key,plaintext,aad=None):
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor()
        if aad: encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag


    def aes256_gcm_decrypt(key,iv,ciphertext,tag,aad=None):
        decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
        if aad: decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

class KEMManager:    
    def __init__(self,algorithm="Classic-McEliece-348864"):
        # Default set to Classic McEliece parameter set 348864
        self.algorithm = algorithm
        self.kem_instance = None
        self.public_key = None
        self.secret_key_bytes = None

    def generate_keypair(self):
        self.kem_instance = oqs.KeyEncapsulation(self.algorithm)
        self.public_key = self.kem_instance.generate_keypair()
        self.secret_key_bytes = self.kem_instance.export_secret_key()
        return self.public_key, self

    def encapsulate(algorithm,public_key):
        kem = oqs.KeyEncapsulation(algorithm)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self,ciphertext):
        if not self.kem_instance:
            raise RuntimeError("No KEM instance available for decapsulation")
        return self.kem_instance.decap_secret(ciphertext)

class SignatureManager:
    def __init__(self,algorithm="SPHINCS+-SHA2-256f-simple"):
        self.algorithm = algorithm
        self.sig_instance = None
        self.public_key = None
        self.secret_key_bytes = None

    def generate_keypair(self):
        self.sig_instance = oqs.Signature(self.algorithm)
        self.public_key = self.sig_instance.generate_keypair()
        self.secret_key_bytes = self.sig_instance.export_secret_key()
        return self.public_key, self
    
    def sign(self,message):
        if not self.sig_instance:
            raise RuntimeError("No signature instance available for signing")
        return self.sig_instance.sign(message)

    def verify(algorithm,message,signature,public_key):
        try:
            sig = oqs.Signature(algorithm)
            return sig.verify(message,signature,public_key)
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False

class Certificate:
    def create_cert(kem_pub,sig_pub,sig_manager):
        # message to be signed is KEM public key concatenated with signature public key
        message = kem_pub + sig_pub
        signature = sig_manager.sign(message)
        
        # Certificate: [kem_pub_len][kem_pub][sig_pub_len][sig_pub][sig_len][signature]
        cert = b''
        cert += PQCrypto.write_u32_be(len(kem_pub))
        cert += kem_pub
        cert += PQCrypto.write_u32_be(len(sig_pub))
        cert += sig_pub
        cert += PQCrypto.write_u32_be(len(signature))
        cert += signature
        return cert
    
    
    def parse_cert(cert):
        pos = 0

        kem_len = PQCrypto.read_u32_be(cert[pos:pos+4])
        pos += 4
        kem_pub = cert[pos:pos+kem_len]
        pos += kem_len
        
        sig_len = PQCrypto.read_u32_be(cert[pos:pos+4])
        pos += 4
        sig_pub = cert[pos:pos+sig_len]
        pos += sig_len
        
        sigblob_len = PQCrypto.read_u32_be(cert[pos:pos+4])
        pos += 4
        signature = cert[pos:pos+sigblob_len]
        
        return kem_pub, sig_pub, signature

class SecureFrame:
    def send_all(sock,data):
        total_sent = 0
        while total_sent<len(data):
            sent = sock.send(data[total_sent:])
            if sent==0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent
    
    def recv_all(sock,length):
        data = b''
        while len(data)<length:
            packet = sock.recv(length-len(data))
            if not packet:
                raise RuntimeError("Socket connection broken")
            data += packet
        return data
    
    
    def send_encrypted_frame(sock,key,plaintext):
        start = time.time()
        iv,ciphertext,tag = PQCrypto.aes256_gcm_encrypt(key,plaintext)
        end = time.time()

        sock.send(PQCrypto.write_u32_be(len(iv)))
        SecureFrame.send_all(sock,iv)
        
        sock.send(PQCrypto.write_u32_be(len(ciphertext)))
        SecureFrame.send_all(sock,ciphertext)

        sock.send(PQCrypto.write_u32_be(len(tag)))
        SecureFrame.send_all(sock,tag)
        return end - start
    
    
    def recv_encrypted_frame(sock,key):
        try:
            iv_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock,4))
            if iv_len==0 or iv_len>64:
                raise ValueError("Invalid IV length")
            iv = SecureFrame.recv_all(sock,iv_len)

            ct_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock,4))
            if ct_len > 64*1024*1024:
                raise ValueError("Ciphertext too large")
            ciphertext = SecureFrame.recv_all(sock,ct_len) if ct_len > 0 else b''
            
            tag_len = PQCrypto.read_u32_be(SecureFrame.recv_all(sock,4))
            if tag_len != 16:
                raise ValueError("Invalid tag length")
            tag = SecureFrame.recv_all(sock,tag_len)
            
            start = time.time()
            pt = PQCrypto.aes256_gcm_decrypt(key,iv,ciphertext,tag)
            end = time.time()
            return pt,end-start

        except Exception as e:
            print(f"Frame receive error: {e}")
            return None
