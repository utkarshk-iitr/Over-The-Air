#!/usr/bin/env python3
"""
Client using RSA-only encrypted frames. Client generates RSA keypair and sends public
key to server after verifying server certificate. All subsequent messages are RSA-encrypted:
  - client -> server: encrypted with server_pub
  - server -> client: encrypted with client private key (server uses client's pub)
"""

import socket
import sys
from rsa_crypto import *
import pyexcel as pe
import time
from merkle import *
import random, string
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
        f_mtree = MerkleTree(f)
        auth_path = f_mtree.getAuthenticationPath(Node.hash(str(f[i_val])), i_val)
    else:
        f_star_mtree = MerkleTree(f_star)
        auth_path = f_star_mtree.getAuthenticationPath(Node.hash(str(f_star[i_val])), i_val)

    T2 = get_timestamp()

    proof_msg = (f"{A},{B},{C}"+"&" + str(auth_path)+"&" + str(R_auth)+"&" + str(T2))
    SecureFrame.send_encrypted_frame(veh_conn, key, proof_msg.encode())
  

class PQClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.current_version = "1.0.0"
        self.available_version = "1.0.0"
        self.VID = "KAF91EA"

    def connect_and_handshake(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            start = time.time()
            self.sock.connect((self.host, self.port))
            print(f"[client] Connected to {self.host}:{self.port}")

            # receive server certificate
            cert_len = PQCrypto.read_u32_be(SecureFrame.recv_all(self.sock, 4))
            cert = SecureFrame.recv_all(self.sock, cert_len)
            server_pub, signature = Certificate.parse_cert(cert)

            # verify cert signature (server signed its own pub in this simplified model)
            if not RSAKeyManager.verify(server_pub, server_pub, signature):
                raise ValueError("Server certificate signature invalid")

            self.server_pub = server_pub

            # generate client RSA keypair and send client's pub to server
            client_rsa = RSAKeyManager(2048)
            client_pub, client_rsa = client_rsa.generate_keypair()
            self.client_rsa_manager = client_rsa

            # send client_pub (u32 len + bytes)
            self.sock.send(PQCrypto.write_u32_be(len(client_pub)))
            SecureFrame.send_all(self.sock, client_pub)

            print("[client] Exchanged public keys (RSA) in",time.time()-start)
            li.append(time.time()-start)
            return True

        except Exception as e:
            print(f"[client] Handshake failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def show_menu(self):
        print("\n" + "=" * 40)
        print("Welcome to the Car Update Server!")
        print("1. Check for updates")
        print("2. Download updates")
        print("3. Install updates")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()
        return choice

    def check_updates(self):
        SecureFrame.send_encrypted_frame(self.sock, self.server_pub, b"check")
        response,t = SecureFrame.recv_encrypted_frame(self.sock, self.client_rsa_manager)
        if response:
            self.available_version = response.decode()
            print(f"Current version: {self.current_version}")
            print(f"Available version: {self.available_version}")

    def download_updates(self):
        if self.current_version == self.available_version:
            print("No updates available")
            return

        command = f"get {self.available_version}"
        SecureFrame.send_encrypted_frame(self.sock, self.server_pub, command.encode())

        start = time.time()
        zkp_prover(self.sock, self.client_rsa_manager, self.server_pub, self.VID)
        res,t = SecureFrame.recv_encrypted_frame(self.sock, self.client_rsa_manager)

        if res.decode() != "YES":
            print("[client] Zero-Knowledge Proof failed")
            return

        print("[client] Zero-Knowledge Proof succeeded in", time.time() - start)
        li.append(time.time() - start)
        response,t = SecureFrame.recv_encrypted_frame(self.sock, self.client_rsa_manager)
        if not response or response.decode() != "OK":
            print(f"Server replied: {response.decode() if response else 'No response'}")
            return

        filename = f"car_update_{self.available_version}.exe"
        print(f"Receiving {filename}...")
        start = time.time()
        ans = 0
        try:
            with open(filename, 'wb') as f:
                while True:
                    chunk,t = SecureFrame.recv_encrypted_frame(self.sock, self.client_rsa_manager)
                    ans += t
                    if chunk is None:
                        print("Transfer aborted")
                        break
                    if len(chunk) == 0:
                        break
                    f.write(chunk)

            print("File downloaded successfully in", time.time() - start)
            li.append(time.time() - start)
            print("Decryption time:", ans)
            li.append(ans)
            fw.writerow(li)
            li.clear()

        except Exception as e:
            print(f"File download error: {e}")

    def install_updates(self):
        print("[client] Installing update...")
        self.current_version = self.available_version

    def send_command(self, command):
        SecureFrame.send_encrypted_frame(self.sock, self.server_pub, command.encode())
        response,t = SecureFrame.recv_encrypted_frame(self.sock, self.client_rsa_manager)
        if response:
            print(response.decode())

    def run(self):
        if not self.connect_and_handshake():
            return

        try:
            while True:
                choice = self.show_menu()

                if choice == "1":
                    self.check_updates()
                elif choice == "2":
                    self.download_updates()
                elif choice == "3":
                    self.install_updates()
                elif choice == "4":
                    SecureFrame.send_encrypted_frame(self.sock, self.server_pub, b"close")
                    response = SecureFrame.recv_encrypted_frame(self.sock, self.client_rsa_manager)[0]
                    if response:
                        print(response.decode())
                    break
                else:
                    self.send_command(choice)

        except KeyboardInterrupt:
            print("\n[client] Interrupted by user")
        finally:
            self.sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    client = PQClient(sys.argv[1], int(sys.argv[2]))
    client.run()
    f2.close()
