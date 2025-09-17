#!/usr/bin/env python3
"""
Post-Quantum Cryptography Client
Connects to PQ server for secure communication
Changed to use Classic McEliece KEM and SPHINCS+ signatures.
"""

import socket
import sys
from mceliece_crypto import *
import pyexcel as pe
import time
from merkle import *
import random,string
import csv

f2 = open("client_time.csv", "a", newline="")
fw = csv.writer(f2)
li = []

def zkp_prover(veh_conn,key,VID):
    prime_field = 17
    w = 7
    N = 16
    ID_size = 7
    reg_sheet1 = pe.get_sheet(file_name="FRI_TA_Reg.xlsx")

    SecureFrame.send_encrypted_frame(veh_conn,key,VID.encode())
    Auth_Req_VPR_T1,t = SecureFrame.recv_encrypted_frame(veh_conn,key)
    Auth_Req_VPR_T1 = Auth_Req_VPR_T1.decode().split('&')

    if len(Auth_Req_VPR_T1)!=3:
        print("Unable to fetch vehicle details correctly")
        exit(0)

    Auth_Req = Auth_Req_VPR_T1[0]
    VPR_star = Auth_Req_VPR_T1[1]
    T1 = float(Auth_Req_VPR_T1[2])
    found = 0

    if Auth_Req=="A1" and get_timestamp()-T1<4:
        for row in reg_sheet1:
            if row[1]==VPR_star:
                alpha = row[2]
                MR_fx = row[4]
                MR_fstar = row[5]
                found = 1 
                break

        if found!=1:
            print("Vehicle not registered")
            exit(0)

        i_val = random.randint(0,N//2-1)
        ti = random.randint(0,1)
        R_auth = random.randint(100,100000)
        T2 = get_timestamp()
        ti_R_auth_i_val_T2 = str(ti)+"&"+str(R_auth)+"&"+str(i_val)+"&"+str(T2)

        SecureFrame.send_encrypted_frame(veh_conn,key,ti_R_auth_i_val_T2.encode())
        proof_pi_R_auth_T3, t = SecureFrame.recv_encrypted_frame(veh_conn,key)

        proof_pi_R_auth_T3 = proof_pi_R_auth_T3.decode().split('&')
        ABC = proof_pi_R_auth_T3[0]
        Authpath_ti = eval(proof_pi_R_auth_T3[1])
        R_auth_star = int(proof_pi_R_auth_T3[2])
        T3 = float(proof_pi_R_auth_T3[3])

        if get_timestamp()-T3<4 and R_auth_star==R_auth:
            if ti==0: merkle_ver_status = Ver_merkle_path(Authpath_ti,MR_fx)
            elif ti==1: merkle_ver_status = Ver_merkle_path(Authpath_ti,MR_fstar)

            if merkle_ver_status!=1:
                print("Merkle verification failed")
                exit(0)

            ABC_proof_list = [int(i) for i in ABC.split(',')]
            y_values = [ABC_proof_list[0],ABC_proof_list[1]]
            w_minus_i_mod_p = pow(w,-i_val,prime_field)
            inv_2_mod_p = pow(2,-1,prime_field)

            term1 = 1+alpha*w_minus_i_mod_p
            term2 = 1-alpha*w_minus_i_mod_p

            y3_for_alpha = ((term1*y_values[0] + term2*y_values[1])*inv_2_mod_p)%prime_field

            if y3_for_alpha == ABC_proof_list[2]:
                VIDnew  = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(ID_size))
                S_auth = random.randint(100, 10000)
                VIDnew_Hand_status_S_auth = VIDnew + "&"+ "S" + "&"+ str(S_auth)
                SecureFrame.send_encrypted_frame(veh_conn,key,VIDnew_Hand_status_S_auth.encode())
                        
            else :
                Auth_status = "F"
                SecureFrame.send_encrypted_frame(veh_conn,key,Auth_status.encode())                


class PQClient:
    def __init__(self,host,port):
        self.host = host
        self.port = port
        # set to match server defaults
        self.kem_alg = "Classic-McEliece-348864"
        self.sig_alg = "SPHINCS+-SHA2-256f-simple"
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
            kem_pub, sig_pub, signature = Certificate.parse_cert(cert)
            message = kem_pub + sig_pub

            if not SignatureManager.verify(self.sig_alg,message,signature,sig_pub):
                raise ValueError("Server certificate signature invalid")
            
            print(f"[client] Received server certificate ({len(cert)} bytes)")
            
            ciphertext, shared_secret = KEMManager.encapsulate(self.kem_alg,kem_pub)
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
