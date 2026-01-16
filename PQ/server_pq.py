#!/usr/bin/env python3
"""
Post-Quantum Cryptography Server
Handles secure connections using Kyber KEM and Dilithium signatures
"""

import socket
import threading
import sys
from pqcrypto import *
from merkle import *
import pyexcel as pe
import time
import csv

f = open("server_time.csv", "a", newline="")
fw = csv.writer(f)
li = []

def get_ip():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def zkp_verifier(client_sock, key):
    N = 16
    prime_field = 17
    w = 7

    reg_sheet1 = pe.get_sheet(file_name="FRI_Veh_Reg.xlsx")
    VID, _ = SecureFrame.recv_encrypted_frame(client_sock, key)
    VID = VID.decode()

    found = 0
    for row in reg_sheet1:
        if row[1] == VID:
            VPR = row[2]
            f = [int(i) for i in row[3].split(',')]
            f_star = [int(i) for i in row[4].split(',')]
            MR_fx = row[5]
            MR_fstar = row[6]
            alpha = row[7]
            found = 1
            break

    if found != 1:
        SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
        return 'F'

    i_val = random.randint(0, N//2 - 1)
    t = random.randint(0, 1)
    R_auth = random.randint(100, 100000)
    T1 = get_timestamp()

    chall = f"{VPR}&{t}&{i_val}&{R_auth}&{T1}"
    SecureFrame.send_encrypted_frame(client_sock, key, chall.encode())

    proof_msg, _ = SecureFrame.recv_encrypted_frame(client_sock, key)
    proof_msg = proof_msg.decode().split('&')

    if len(proof_msg) != 4:
        SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
        return 'F'

    ABC, auth_path, R_auth_star, T2 = proof_msg
    A, B, C = map(int, ABC.split(','))
    R_auth_star = int(R_auth_star)
    T2 = float(T2)

    if R_auth_star != R_auth or get_timestamp() - T2 > 4:
        SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
        return 'F'

    auth_path = eval(auth_path)
    if t == 0:
        if Ver_merkle_path(auth_path, MR_fx) != 1:
            SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
            return 'F'
    else:
        if Ver_merkle_path(auth_path, MR_fstar) != 1:
            SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
            return 'F'

    w_inv = pow(w, -i_val, prime_field)
    inv2 = pow(2, -1, prime_field)

    y = ((1 + alpha * w_inv) * A + (1 - alpha * w_inv) * B) * inv2
    y %= prime_field

    if y != C:
        SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
        return 'F'
        
    SecureFrame.send_encrypted_frame(client_sock, key, b"YES")
    return 'S'



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
            start = time.time()
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
            
            print("[server] Secure handshake completed in",time.time()-start,"\n")
            li.append(time.time()-start)
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
                plaintext, t = SecureFrame.recv_encrypted_frame(client_sock,key)
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
        start = time.time()
        if zkp_verifier(client_sock,key)!='S':
            print("[server] Zero-Knowledge Proof failed")
            SecureFrame.send_encrypted_frame(client_sock,key,b"NO")
            return
        print("[server] Zero-Knowledge Proof succeeded in",time.time()-start)
        li.append(time.time()-start)
        SecureFrame.send_encrypted_frame(client_sock,key,b"YES")
        filename = f"update_{version}.exe"
        start = time.time()
        
        ans = 0
        try:
            with open(filename,'rb') as f:
                ans += SecureFrame.send_encrypted_frame(client_sock,key,b"OK")
                chunk_size = 4096
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        SecureFrame.send_encrypted_frame(client_sock,key,b"")
                        break
                    SecureFrame.send_encrypted_frame(client_sock,key,chunk)
            print("[server] File transfer completed in",time.time()-start)
            li.append(time.time()-start)
            print(f"Encryption time: {ans} seconds")
            li.append(ans)
            fw.writerow(li)
            li.clear()

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
    f.close()
