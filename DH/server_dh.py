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
