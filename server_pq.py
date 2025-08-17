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

def get_ip():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def zkp_verifier(client_sock,key):
    N = 16
    reg_sheet1 = pe.get_sheet (file_name= "FRI_Veh_Reg.xlsx")
    auth_sheet1 = pe.get_sheet (file_name= "FRI_Veh_Auth.xlsx")
    VID = SecureFrame.recv_encrypted_frame(client_sock,key)
    print ("VID : ", VID)

    for row in reg_sheet1 : # [ fx_list, VID, VPR, RSU_comp_time, MR_fx, MR_fstar, f_w_i, f_star_w_2i ]
        if row[1] == VID :
            VPR = row[2]
            f_w_i = [int(i) for i in row[3].split(',')]
            f_star_w_2i = [int(i) for i in row[4].split(',')]
            reg_flag = 1 
            print ("  VID : ", VID, "match found ...")
            break

    if reg_flag == 1 : 
        f_w_i_root_hash, f_w_i_mtree_obj = mixmerkletree (f_w_i)
        f_star_w_2i_root_hash, f_star_w_2i_mtree_obj = mixmerkletree (f_star_w_2i)

        T1 = str(get_timestamp ())
        Auth_Req_VPR_T1 = "A1" + "&"+ VPR +"&"+ T1

        len_Auth_Req_VPR_T1 = len(Auth_Req_VPR_T1)

        print ("Send Len of  Auth_Req_VPR_T1 : ", len_Auth_Req_VPR_T1 )
        print ("Sedning to RSU1 : ", Auth_Req_VPR_T1)
        
        client_sock.send (Auth_Req_VPR_T1.encode('utf')) 
        ti_R_auth_i_val_T2 = client_sock.recv(1024).decode()  # receive (alpha) from Veh

        len_ti_R_auth_i_val_T2 = len (ti_R_auth_i_val_T2)
        print ("Recv Len of len_R_reg_alpha_T2 : ", len_ti_R_auth_i_val_T2)

        start1_comp_time = time.time ()
        ti_R_auth_i_val_T2 = [i for i in ti_R_auth_i_val_T2.split('&')]

        ti = ti_R_auth_i_val_T2[0]
        R_auth = ti_R_auth_i_val_T2[1]
        i_val = int(ti_R_auth_i_val_T2[2])
        T2 = float (ti_R_auth_i_val_T2[3])

        if get_timestamp () - T2 < 4 :

            print ("Received Challenge \nti = ", ti, "\ni_val = ", i_val)
 
            get_f_w_i_val = f_w_i[i_val]
            get_f_w_N2_i = f_w_i[int(N//2) + i_val]
            get_f_star_w_2i = f_star_w_2i[i_val]

            ABC_proof = [get_f_w_i_val, get_f_w_N2_i, get_f_star_w_2i]
            ABC_proof = listToString(ABC_proof)

            if ti == "0" :
                auth_path_for_ti = f_w_i_mtree_obj.getAuthenticationPath(Node.hash(str(f_w_i[i_val])), i_val)

            elif ti == "1" :
                auth_path_for_ti = f_star_w_2i_mtree_obj.getAuthenticationPath(Node.hash(str(f_star_w_2i[i_val])), i_val)

            auth_path_for_ti = str(auth_path_for_ti)

            T3 = get_timestamp ()

            proof_pi_R_auth_T3 = ABC_proof + "&"+ auth_path_for_ti + "&"+ R_auth + "&"+ str(T3)

            end1_comp_time = time.time ()
            comp_time = end1_comp_time - start1_comp_time

            len_proof_pi_R_auth_T3 = len(proof_pi_R_auth_T3)

            print ("Send Len of  proof_pi_R_auth_T3 : ", len_proof_pi_R_auth_T3 )

            client_sock.send (proof_pi_R_auth_T3.encode('utf')) 
            VIDnew_Auth_status_S_auth = client_sock.recv(1024).decode()  # Auth status from RSU1

            len_VIDnew_Auth_status_S_auth = len (VIDnew_Auth_status_S_auth)
            print ("Recv Len of len_R_reg_alpha_T2 : ", len_VIDnew_Auth_status_S_auth)

            VIDnew_Auth_status_S_auth = [i for i in VIDnew_Auth_status_S_auth.split('&')]
            VIDnew = VIDnew_Auth_status_S_auth[0]
            S_auth = VIDnew_Auth_status_S_auth[2]

            if VIDnew_Auth_status_S_auth[1] == "S" :
                auth_sheet1.row += [ VID, VIDnew, S_auth, comp_time ]
                auth_sheet1.save_as ("FRI_Veh_Auth.xlsx")
                return 'S'
        else :
            return 'F'
    else :
        return 'F'


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
        if zkp_verifier(client_sock,key)!='S':
            print("Zero-Knowledge Proof failed")
            return
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
