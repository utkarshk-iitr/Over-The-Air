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


def zkp_prover(veh_conn,key):
    prime_field = 17            # w= 7 (generator), F_p field
    w = 7
    N = 16
    ID_size = 7
    reg_sheet1 = pe.get_sheet (file_name= "FRI_TA_Reg.xlsx")
    auth_sheet1 = pe.get_sheet (file_name= "FRI_RSU1_Auth.xlsx")

    fetch_reg_details = 0
    VID = "1NT9CRE"
    SecureFrame.send_encrypted_frame(veh_conn,key,VID.encode())
    Auth_Req_VPR_T1 =  SecureFrame.recv_encrypted_frame(veh_conn,key).decode()
    Auth_Req_VPR_T1 = [i for i in Auth_Req_VPR_T1.split('&')]   

    Auth_Req = Auth_Req_VPR_T1[0]
    VPR_star = Auth_Req_VPR_T1[1]
    T1 = float(Auth_Req_VPR_T1[2])

    start_latency = time.time()
    start1_comp_time = time.time()

    if Auth_Req == "A1" and get_timestamp() - T1 < 4 :
        for row in reg_sheet1 :
            if row[1] == VPR_star :
                VPR = row[1]
                alpha = row[2]
                MR_fx = row[4]
                MR_fstar = row[5]
                fetch_reg_details = 1 
                break

        if fetch_reg_details == 1 :
            i_val = random.randint(0,N//2-1)
            ti = random.randint(0, 1)
            T2 = get_timestamp ()
            R_auth = random.randint(100, 100000)
                
            ti_R_auth_i_val_T2 = str(ti)+ "&"+ str(R_auth) + "&"+ str(i_val) + "&"+ str(T2)
            end1_comp_time = time.time ()

            auth_comp_time = end1_comp_time - start1_comp_time

            SecureFrame.send_encrypted_frame(veh_conn,key,ti_R_auth_i_val_T2.encode())
            proof_pi_R_auth_T3 = SecureFrame.recv_encrypted_frame(veh_conn,key).decode()

            proof_pi_R_auth_T3 = [i for i in proof_pi_R_auth_T3.split('&')]
            start2_comp_time = time.time ()
            ABC = proof_pi_R_auth_T3[0]
            Authpath_ti = eval(proof_pi_R_auth_T3[1])
            R_auth_star = int(proof_pi_R_auth_T3[2])
            T3 = proof_pi_R_auth_T3[3]

            if get_timestamp () - float(T3) < 4 and R_auth_star == R_auth :

                if ti == 0 :
                    merkle_ver_status = Ver_merkle_path (Authpath_ti, MR_fx )
                elif ti == 1 :
                    merkle_ver_status = Ver_merkle_path (Authpath_ti, MR_fstar )

                if merkle_ver_status == 1 :
                    ABC_proof_list = [int(i) for i in ABC.split(',')]

                    x_values = [ (w**i_val) % prime_field, (w**(N//2+ i_val)) % prime_field] #, alpha 
                    y_values = [ ABC_proof_list[0] , ABC_proof_list[1] ]
                    w_minus_i_mod_p = pow(w, -i_val, prime_field)
                    inv_2_mod_p = pow(2, -1, prime_field)

                    term1 = 1 + alpha * w_minus_i_mod_p 
                    term2 = 1 - alpha * w_minus_i_mod_p

                    y3_for_alpha = ((term1 *  y_values[0] + term2 * y_values[1] ) * inv_2_mod_p) % prime_field

                    if y3_for_alpha == ABC_proof_list[2]:
                        VIDnew  = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(ID_size))
                        S_auth = random.randint(100, 10000)

                        end2_comp_time = time.time () 
                        auth_comp_time += end2_comp_time - start2_comp_time

                        VIDnew_Hand_status_S_auth = VIDnew + "&"+ "S" + "&"+ str(S_auth)
                        SecureFrame.send_encrypted_frame(veh_conn,key,VIDnew_Hand_status_S_auth.encode())

                        end_latency = time.time ()
                        total_latency = end_latency - start_latency
                        auth_sheet1.row += [ VIDnew, S_auth, auth_comp_time, total_latency ]
                        auth_sheet1.save_as ("FRI_RSU1_Auth.xlsx")
                                
                    else :
                        Auth_status = "F"
                        SecureFrame.send_encrypted_frame(veh_conn,key,Auth_status.encode())                


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

        zkp_prover(self.sock,self.aes_key)
        res = SecureFrame.recv_encrypted_frame(self.sock,self.aes_key).decode()

        if(res != "YES"):
            print("[client] Zero-Knowledge Proof failed")
            return

        print("[client] Zero-Knowledge Proof succeeded")

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
