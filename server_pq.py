#!/usr/bin/env python3
"""
Post-Quantum Cryptography Server
Handles secure connections using Kyber KEM and Dilithium signatures
"""

import socket
import threading
import sys
from pqcrypto import *

def get_ip():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

class PQServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.kem_alg = "Kyber768"
        self.sig_alg = "Dilithium3"
        self.server_version = "1.0.3"

    def handle_client(self,client_sock,client_addr):
        print(f"[server] Client connected: {client_addr}")
        
        try:
            kem_manager = KEMManager(self.kem_alg)
            kyber_pub, kem_manager = kem_manager.generate_keypair()

            sig_manager = SignatureManager(self.sig_alg)
            dilithium_pub, sig_manager = sig_manager.generate_keypair()
            
            cert = Certificate.create_cert(kyber_pub,dilithium_pub,sig_manager)
            client_sock.send(PQCrypto.write_u32_be(len(cert)))
            SecureFrame.send_all(client_sock,cert)
            
            ct_len = PQCrypto.read_u32_be(SecureFrame.recv_all(client_sock,4))
            ciphertext = SecureFrame.recv_all(client_sock,ct_len)
            shared_secret = kem_manager.decapsulate(ciphertext)
            
            salt = b"server-salt-v1"
            info = b"pq-handshake-v1"
            aes_key = PQCrypto.hkdf_sha256(shared_secret,salt,info,32)
            shared_secret = bytearray(shared_secret)
            PQCrypto.secure_clear(shared_secret)
            
            print("[server] Secure handshake completed\n")
            self.command_loop(client_sock,aes_key)
            
        except Exception as e:
            print(f"[server] Error handling client {client_addr}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_sock.close()
            print(f"[server] Client {client_addr} disconnected\n")
    
    def command_loop(self,client_sock,key):
        while True:
            try:
                plaintext = SecureFrame.recv_encrypted_frame(client_sock,key)
                if plaintext is None:
                    break
                
                command = plaintext.decode('utf-8')
                print(f"[server] Received command: {command}")
                
                if command=="close":
                    response = "Closing connection...\n"
                    SecureFrame.send_encrypted_frame(client_sock,key,response.encode())
                    break
                    
                elif command=="check":
                    SecureFrame.send_encrypted_frame(client_sock,key,self.server_version.encode())

                elif command.startswith("get "):
                    version = command[4:]
                    self.handle_file_download(client_sock,key,version)

                else:
                    response = "Invalid command\n"
                    SecureFrame.send_encrypted_frame(client_sock,key,response.encode())

            except Exception as e:
                print(f"[server] Command processing error: {e}")
                break
    
    def handle_file_download(self,client_sock,key,version):
        filename = f"update_{version}.exe"
        
        try:
            with open(filename,'rb') as f:
                SecureFrame.send_encrypted_frame(client_sock,key,b"OK")
                chunk_size = 4096
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        SecureFrame.send_encrypted_frame(client_sock,key,b"")
                        break
                    SecureFrame.send_encrypted_frame(client_sock,key,chunk)

        except FileNotFoundError:
            SecureFrame.send_encrypted_frame(client_sock,key,b"NO")

    def start(self):
        server_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        
        try:
            server_sock.bind((self.host,self.port))
            server_sock.listen(16)
            print(f"[server] Listening on {self.host}:{self.port}")
            
            while True:
                client_sock,client_addr = server_sock.accept()
                thread = threading.Thread(target=self.handle_client,args=(client_sock,client_addr))
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            print("\n[server] Shutting down...")
        finally:
            server_sock.close()

if __name__=="__main__":
    if len(sys.argv)!=2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)

    server = PQServer(get_ip(),int(sys.argv[1]))
    server.start()
