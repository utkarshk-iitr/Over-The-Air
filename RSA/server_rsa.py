#!/usr/bin/env python3
"""
Server with RSA-only encrypted frames (no AES).
ZKP / Merkle code unchanged in logic except using RSA framing.
"""

import socket
import threading
import sys
from rsa_crypto import *
from merkle import *
import pyexcel as pe
import time

def get_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def zkp_verifier(client_sock, server_rsa_manager, client_pub_bytes):
    """
    Server decrypts incoming frames with server_rsa_manager,
    and encrypts outgoing frames with client_pub_bytes.
    """
    N = 16
    reg_sheet1 = pe.get_sheet(file_name="FRI_Veh_Reg.xlsx")

    VID_bytes = SecureFrame.recv_encrypted_frame(client_sock, server_rsa_manager)
    VID = VID_bytes.decode()
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
    SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, Auth_Req_VPR_T1.encode())

    ti_R_auth_i_val_T2 = SecureFrame.recv_encrypted_frame(client_sock, server_rsa_manager)
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
        SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, proof_pi_R_auth_T3.encode())

        VIDnew_Auth_status_S_auth = SecureFrame.recv_encrypted_frame(client_sock, server_rsa_manager).decode().split('&')
        if VIDnew_Auth_status_S_auth[1] == "S":
            return 'S'
    else:
        return 'F'


class PQServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_version = "1.0.3"

    def handle_client(self, client_sock, client_addr):
        print(f"[server] Client connected: {client_addr}")

        try:
            # generate server RSA keypair for this connection (could be persistent)
            rsa_manager = RSAKeyManager(2048)
            rsa_pub, rsa_manager = rsa_manager.generate_keypair()

            # create certificate and send to client
            cert = Certificate.create_cert(rsa_pub, rsa_manager)
            client_sock.send(PQCrypto.write_u32_be(len(cert)))
            SecureFrame.send_all(client_sock, cert)

            # receive client's public key (u32 len + bytes)
            client_pub_len = PQCrypto.read_u32_be(SecureFrame.recv_all(client_sock, 4))
            client_pub = SecureFrame.recv_all(client_sock, client_pub_len)

            print("[server] Exchanged public keys with client, entering RSA-only session.")

            self.command_loop(client_sock, rsa_manager, client_pub)

        except Exception as e:
            print(f"[server] Error handling client {client_addr}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_sock.close()
            print(f"[server] Client {client_addr} disconnected\n")

    def command_loop(self, client_sock, server_rsa_manager, client_pub_bytes):
        while True:
            try:
                # decrypt incoming command with server private key
                plaintext = SecureFrame.recv_encrypted_frame(client_sock, server_rsa_manager)
                if plaintext is None:
                    break
                if len(plaintext) == 0:
                    # ignore empty frames
                    continue

                command = plaintext.decode('utf-8')
                print(f"[server] Received command: {command}")

                if command == "close":
                    response = "Closing connection...\n"
                    SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, response.encode())
                    break

                elif command == "check":
                    SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, self.server_version.encode())

                elif command.startswith("get "):
                    version = command[4:]
                    self.handle_file_download(client_sock, server_rsa_manager, client_pub_bytes, version)

                else:
                    response = "Invalid command\n"
                    SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, response.encode())

            except Exception as e:
                print(f"[server] Command processing error: {e}")
                break

    def handle_file_download(self, client_sock, server_rsa_manager, client_pub_bytes, version):
        start = time.time()
        if zkp_verifier(client_sock, server_rsa_manager, client_pub_bytes) != 'S':
            print("[server] Zero-Knowledge Proof failed")
            SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, b"NO")
            return
        
        print("[server] Zero-Knowledge Proof succeeded in", time.time() - start)
        SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, b"YES")
        filename = f"update_{version}.exe"
        start = time.time()

        try:
            with open(filename, 'rb') as f:
                SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, b"OK")
                chunk_size = 4096  # we'll re-chunk on RSA side; this is file read size
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        # send empty frame as end marker
                        SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, b"")
                        break
                    SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, chunk)
            print("[server] File transfer completed in", time.time() - start)

        except FileNotFoundError:
            SecureFrame.send_encrypted_frame(client_sock, client_pub_bytes, b"NO")

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

    server = PQServer(get_ip(), int(sys.argv[1]))
    server.start()
