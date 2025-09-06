#!/usr/bin/env python3
"""
Diffie-Hellman Server
Handles secure connections using DH key exchange + AES-GCM
Simplified version without ZKP authentication
"""

import socket
import threading
import sys
from dh_crypto import *
from merkle import *
import pyexcel as pe
import time
import csv

f = open("server_time.csv", "a", newline="")
fw = csv.writer(f)
li = []

def get_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def zkp_verifier(client_sock, key):
    N = 16
    reg_sheet1 = pe.get_sheet(file_name="FRI_Veh_Reg.xlsx")
    VID, t = SecureFrame.recv_encrypted_frame(client_sock, key)
    VID = VID.decode()
    reg_flag = 0

    for row in reg_sheet1:
        if row[1] == VID:
            VPR = row[2]
            f_w_i = [int(i) for i in row[3].split(',')]
            f_star_w_2i = [int(i) for i in row[4].split(',')]
            reg_flag = 1
            break

    if reg_flag != 1:
        return 'F'

    _, f_w_i_mtree_obj = mixmerkletree(f_w_i)
    _, f_star_w_2i_mtree_obj = mixmerkletree(f_star_w_2i)

    T1 = get_timestamp()
    Auth_Req_VPR_T1 = "A1&" + VPR + "&" + str(T1)
    SecureFrame.send_encrypted_frame(client_sock, key, Auth_Req_VPR_T1.encode())
    ti_R_auth_i_val_T2, t = SecureFrame.recv_encrypted_frame(client_sock, key)
    ti_R_auth_i_val_T2 = ti_R_auth_i_val_T2.decode().split('&')

    ti = ti_R_auth_i_val_T2[0]
    R_auth = ti_R_auth_i_val_T2[1]
    i_val = int(ti_R_auth_i_val_T2[2])
    T2 = float(ti_R_auth_i_val_T2[3])

    if get_timestamp() - T2 < 4:
        get_f_w_i_val = f_w_i[i_val]
        get_f_w_N2_i = f_w_i[int(N // 2) + i_val]
        get_f_star_w_2i = f_star_w_2i[i_val]

        ABC_proof = [get_f_w_i_val, get_f_w_N2_i, get_f_star_w_2i]
        ABC_proof = listToString(ABC_proof)

        if ti == "0":
            auth_path_for_ti = f_w_i_mtree_obj.getAuthenticationPath(Node.hash(str(f_w_i[i_val])), i_val)

        elif ti == "1":
            auth_path_for_ti = f_star_w_2i_mtree_obj.getAuthenticationPath(Node.hash(str(f_star_w_2i[i_val])), i_val)

        auth_path_for_ti = str(auth_path_for_ti)

        T3 = get_timestamp()
        proof_pi_R_auth_T3 = ABC_proof + "&" + auth_path_for_ti + "&" + R_auth + "&" + str(T3)
        SecureFrame.send_encrypted_frame(client_sock, key, proof_pi_R_auth_T3.encode())
        VIDnew_Auth_status_S_auth, t = SecureFrame.recv_encrypted_frame(client_sock, key)
        VIDnew_Auth_status_S_auth = VIDnew_Auth_status_S_auth.decode().split('&')

        if VIDnew_Auth_status_S_auth[1] == "S":
            return 'S'
    else:
        return 'F'

class DHServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_version = "1.0.3"

    def handle_client(self, client_sock, client_addr):
        print(f"[server] Client connected: {client_addr}")

        try:
            start = time.time()
            
            # Generate DH keypair with error handling
            try:
                dh_manager = DHKeyManager(2048)
                dh_pub, dh_params, dh_manager = dh_manager.generate_keypair()
                print(f"[server] DH keypair generated successfully")
            except Exception as e:
                print(f"[server] Failed to generate DH keypair: {e}")
                return

            # Send DH parameters and public key to client
            try:
                client_sock.send(PQCrypto.write_u32_be(len(dh_params)))
                SecureFrame.send_all(client_sock, dh_params)
                
                client_sock.send(PQCrypto.write_u32_be(len(dh_pub)))
                SecureFrame.send_all(client_sock, dh_pub)
                print(f"[server] Sent DH parameters and public key to client")
            except Exception as e:
                print(f"[server] Failed to send DH data to client: {e}")
                return

            # Receive client's public key
            try:
                client_pub_len = PQCrypto.read_u32_be(SecureFrame.recv_all(client_sock, 4))
                client_pub_bytes = SecureFrame.recv_all(client_sock, client_pub_len)
                print(f"[server] Received client public key ({client_pub_len} bytes)")
            except Exception as e:
                print(f"[server] Failed to receive client public key: {e}")
                return

            # Compute shared secret
            try:
                shared_secret = dh_manager.compute_shared_secret(client_pub_bytes)
                print(f"[server] Computed shared secret successfully")
            except Exception as e:
                print(f"[server] Failed to compute shared secret: {e}")
                return

            # Derive AES key from shared secret
            try:
                salt = b"server-salt-v1"
                info = b"dh-handshake-v1"
                aes_key = PQCrypto.hkdf_sha256(shared_secret, salt, info, 32)
                
                # Clear shared secret
                shared_secret = bytearray(shared_secret)
                PQCrypto.secure_clear(shared_secret)

                handshake_time = time.time() - start
                print(f"[server] DH handshake completed in {handshake_time:.4f} seconds\n")
                li.append(handshake_time)
                
                # Start command loop
                self.command_loop(client_sock, aes_key)
                
            except Exception as e:
                print(f"[server] Failed to derive AES key: {e}")
                return

        except Exception as e:
            print(f"[server] Error handling client {client_addr}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                client_sock.close()
            except:
                pass
            print(f"[server] Client {client_addr} disconnected\n")

    def command_loop(self, client_sock, key):
        while True:
            try:
                plaintext, t = SecureFrame.recv_encrypted_frame(client_sock, key)
                if plaintext is None:
                    break

                command = plaintext.decode('utf-8')
                print(f"[server] Received command: {command}")

                if command == "close":
                    response = "Closing connection...\n"
                    SecureFrame.send_encrypted_frame(client_sock, key, response.encode())
                    break

                elif command == "check":
                    SecureFrame.send_encrypted_frame(client_sock, key, self.server_version.encode())

                elif command.startswith("get "):
                    version = command[4:]
                    self.handle_file_download(client_sock, key, version)

                else:
                    response = "Invalid command\n"
                    SecureFrame.send_encrypted_frame(client_sock, key, response.encode())

            except Exception as e:
                print(f"[server] Command processing error: {e}")
                break

    def handle_file_download(self, client_sock, key, version):
        start = time.time()
        if zkp_verifier(client_sock, key) != 'S':
            print("[server] Zero-Knowledge Proof failed")
            SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
            return
        
        print("[server] Zero-Knowledge Proof succeeded in", time.time() - start)
        li.append(time.time() - start)
        SecureFrame.send_encrypted_frame(client_sock, key, b"YES")
        filename = f"update_{version}.exe"
        start = time.time()

        encrypt_time = 0
        try:
            with open(filename, 'rb') as f:
                encrypt_time += SecureFrame.send_encrypted_frame(client_sock, key, b"OK")
                chunk_size = 4096
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        encrypt_time += SecureFrame.send_encrypted_frame(client_sock, key, b"")
                        break
                    encrypt_time += SecureFrame.send_encrypted_frame(client_sock, key, chunk)
            
            transfer_time = time.time() - start
            print(f"[server] File transfer completed in {transfer_time:.4f} seconds")
            print(f"Total encryption time: {encrypt_time:.4f} seconds")
            
            # Log: Handshake, ZKP Time, Transfer Time, Encrypt Time
            li.append(transfer_time)
            li.append(encrypt_time)
            fw.writerow(li)
            li.clear()

        except FileNotFoundError:
            print(f"[server] File not found: {filename}")
            SecureFrame.send_encrypted_frame(client_sock, key, b"NO")

    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(16)
            print(f"[server] Listening on {self.host}:{self.port}")

            while True:
                client_sock, client_addr = server_sock.accept()
                thread = threading.Thread(target=self.handle_client, args=(client_sock, client_addr))
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            print("\n[server] Shutting down...")
        finally:
            server_sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)

    server = DHServer(get_ip(), int(sys.argv[1]))
    server.start()
    f.close()
