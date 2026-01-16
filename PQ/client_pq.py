#!/usr/bin/env python3
"""
Post-Quantum Cryptography Client
Connects to PQ server for secure communication
"""

import socket
import sys
from pqcrypto import *
import pyexcel as pe
import time
from merkle import *
import random,string
import csv

f2 = open("client_time.csv", "a", newline="")
fw = csv.writer(f2)
li = []

def zkp_prover(veh_conn, key, VID):
    prime_field = 17
    w = 7
    N = 16

    reg_sheet1 = pe.get_sheet(file_name="FRI_TA_Reg.xlsx")

    SecureFrame.send_encrypted_frame(veh_conn, key, VID.encode())
    chall, _ = SecureFrame.recv_encrypted_frame(veh_conn, key)
    chall = chall.decode().split('&')

    if len(chall) != 5:
        return

    VPR, t, i_val, R_auth, T1 = chall
    t = int(t)
    i_val = int(i_val)
    R_auth = int(R_auth)
    T1 = float(T1)

    if get_timestamp() - T1 > 4:
        return

    found = 0
    for row in reg_sheet1:
        if row[1] == VPR:
            alpha = row[2]
            f = [int(x) for x in row[3].split(',')]
            f_star = [int(x) for x in row[6].split(',')]
            MR_fx = row[4]
            MR_fstar = row[5]
            found = 1
            break

    if found != 1:
        return

    A = f[i_val]
    B = f[N//2 + i_val]
    C = f_star[i_val]

    if t == 0:
        auth_path = MerklePath(f, i_val)
    else:
        auth_path = MerklePath(f_star, i_val)

    T2 = get_timestamp()

    proof_msg = (
        f"{A},{B},{C}"
        "&" + str(auth_path)
        "&" + str(R_auth)
        "&" + str(T2)
    )
    SecureFrame.send_encrypted_frame(veh_conn, key, proof_msg.encode())
          


class PQClient:
    def __init__(self,host,port):
        self.host = host
        self.port = port
        self.kem_alg = "Kyber768"
        self.sig_alg = "Dilithium3"
        self.current_version = "1.0.0"
        self.available_version = "1.0.0"
        self.VID = "KAF91EA"

    def connect_and_handshake(self):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        
        try:
            start = time.time()
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
            print("[client] Secure handshake completed in",time.time()-start)
            li.append(time.time()-start)
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
        response, t = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
        if response:
            self.available_version = response.decode()
            print(f"Current version: {self.current_version}")
            print(f"Available version: {self.available_version}")
    
    def download_updates(self):
        if(self.current_version==self.available_version):
            print("No updates available")
            return
        
        command = f"get {self.available_version}"
        SecureFrame.send_encrypted_frame(self.sock,self.aes_key,command.encode())

        start = time.time()
        zkp_prover(self.sock,self.aes_key,self.VID)
        res, t = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)

        if res.decode()!="YES":
            print("[client] Zero-Knowledge Proof failed")
            return

        print("[client] Zero-Knowledge Proof succeeded in",time.time()-start)
        li.append(time.time()-start)
        response,t = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
        if not response or response.decode()!="OK":
            print(f"Server replied: {response.decode() if response else 'No response'}")
            return
        
        filename = f"car_update_{self.available_version}.exe"
        print(f"Receiving {filename}...")
        start = time.time()
        ans = 0
        try:
            with open(filename,'wb') as f:
                while True:
                    chunk,t = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
                    ans += t
                    if chunk is None:
                        print("Transfer aborted")
                        break
                    if len(chunk)==0: break
                    f.write(chunk)

            print("File downloaded successfully in",time.time()-start)
            li.append(time.time()-start)
            print(f"Decryption time: {ans} seconds")
            li.append(ans)
            fw.writerow(li)
            li.clear()

        except Exception as e:
            print(f"File download error: {e}")
    
    def install_updates(self):
        print("[client] Installing update...")
        self.current_version = self.available_version
    
    def send_command(self,command):
        SecureFrame.send_encrypted_frame(self.sock,self.aes_key,command.encode())
        response, t = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
        if response: print(response.decode())
    
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
                    response, t = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key)
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
    f2.close()
