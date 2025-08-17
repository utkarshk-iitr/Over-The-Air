#!/usr/bin/env python3
"""
Post-Quantum Cryptography Client
Connects to PQ server for secure communication
"""

import socket
import sys
from pqcrypto import *

class PQClient:
    def __init__(self,host,port):
        self.host = host
        self.port = port
        self.kem_alg = "Kyber768"
        self.sig_alg = "Dilithium3"
        self.current_version = "1.0.0"
        self.available_version = "1.0.0"
    
    def connect_and_handshake(self):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        
        try:
            self.sock.connect((self.host, self.port))
            print(f"[client] Connected to {self.host}:{self.port}")

            cert_len = PQCrypto.read_u32_be(SecureFrame.recv_all(self.sock,4))
            cert = SecureFrame.recv_all(self.sock,cert_len)

            kyber_pub, dilithium_pub, signature = Certificate.parse_cert(cert)
            message = kyber_pub + dilithium_pub
            if not SignatureManager.verify(self.sig_alg,message,signature,dilithium_pub):
                raise ValueError("Server certificate signature invalid")
            
            print(f"[client] Received server certificate ({len(cert)} bytes)")
            
            ciphertext, shared_secret = KEMManager.encapsulate(self.kem_alg,kyber_pub)
            self.sock.send(PQCrypto.write_u32_be(len(ciphertext)))
            SecureFrame.send_all(self.sock,ciphertext)
            
            salt = b"server-salt-v1"
            info = b"pq-handshake-v1"
            self.aes_key = PQCrypto.hkdf_sha256(shared_secret,salt,info,32)

            shared_secret = bytearray(shared_secret)
            PQCrypto.secure_clear(shared_secret)
            print("[client] Secure handshake completed")
            return True
            
        except Exception as e:
            print(f"[client] Handshake failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def show_menu(self):
        print("\n" + "="*40)
        print("Welcome to the Car Update Server!")
        print("1. Check for updates")
        print("2. Download updates")
        print("3. Install updates")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()
        return choice
    
    def check_updates(self):
        SecureFrame.send_encrypted_frame(self.sock,self.aes_key,b"check")
        response = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
        if response:
            self.available_version = response.decode('utf-8')
            print(f"Current version: {self.current_version}")
            print(f"Available version: {self.available_version}")
    
    def download_updates(self):
        if(self.current_version==self.available_version):
            print("No updates available")
            return
        
        command = f"get {self.available_version}"
        SecureFrame.send_encrypted_frame(self.sock,self.aes_key,command.encode())
        
        response = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
        if not response or response.decode()!="OK":
            print(f"Server replied: {response.decode() if response else 'No response'}")
            return
        
        filename = f"car_update_{self.available_version}.exe"
        print(f"Receiving {filename}...")
        
        try:
            with open(filename,'wb') as f:
                while True:
                    chunk = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
                    if chunk is None:
                        print("Transfer aborted")
                        break
                    if len(chunk)==0:
                        break
                    f.write(chunk)
            
            print("File downloaded successfully")
            
        except Exception as e:
            print(f"File download error: {e}")
    
    def install_updates(self):
        print("[client] Installing update...")
        self.current_version = self.available_version
    
    def send_command(self,command):
        SecureFrame.send_encrypted_frame(self.sock,self.aes_key,command.encode())
        response = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
        if response:
            print(response.decode())
    
    def run(self):
        if not self.connect_and_handshake():
            return
        
        try:
            while True:
                choice = self.show_menu()

                if choice=="1": self.check_updates()
                elif choice=="2": self.download_updates()
                elif choice=="3": self.install_updates()
                elif choice=="4":
                    SecureFrame.send_encrypted_frame(self.sock,self.aes_key,b"close")
                    response = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
                    if response: print(response.decode())
                    break
                else:
                    self.send_command(choice)
        
        except KeyboardInterrupt:
            print("\n[client] Interrupted by user")
        finally:
            if hasattr(self,'aes_key'):
                key = bytearray(self.aes_key)
                PQCrypto.secure_clear(key)
            self.sock.close()

if __name__=="__main__":
    if len(sys.argv)!=3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    client = PQClient(sys.argv[1],int(sys.argv[2]))
    client.run()
