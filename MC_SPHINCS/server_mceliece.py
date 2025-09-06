#!/usr/bin/env python3
"""
Classic McEliece (KEM) + SPHINCS+ (signatures) OTA Server
- Cert: SPHINCS+ signs (KEM_pub || SIG_pub)
- Handshake: Client encapsulates to server's McEliece KEM pub -> shared secret -> HKDF -> AES-256-GCM key
- After ZKP/Merkle auth, streams encrypted file
"""

import socket, threading, sys, time, csv
from mceliece_crypto import *
from merkle import *
import pyexcel as pe

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

    VID, _ = SecureFrame.recv_encrypted_frame(client_sock, key)
    if VID is None: return 'F'
    VID = VID.decode()

    reg_flag = 0
    for row in reg_sheet1:
        if row[1] == VID:
            VPR = row[2]
            f_w_i = [int(i) for i in row[3].split(',')]
            f_star_w_2i = [int(i) for i in row[4].split(',')]
            reg_flag = 1
            break
    if reg_flag != 1: return 'F'

    _, mt_fw = mixmerkletree(f_w_i)
    _, mt_fstar = mixmerkletree(f_star_w_2i)

    T1 = get_timestamp()
    Auth_Req_VPR_T1 = "A1&" + VPR + "&" + str(T1)
    SecureFrame.send_encrypted_frame(client_sock, key, Auth_Req_VPR_T1.encode())

    ti_R_auth_i_val_T2, _ = SecureFrame.recv_encrypted_frame(client_sock, key)
    if ti_R_auth_i_val_T2 is None: return 'F'
    ti, R_auth, i_val_s, T2s = ti_R_auth_i_val_T2.decode().split('&')
    i_val = int(i_val_s); T2 = float(T2s)

    if get_timestamp() - T2 < 4:
        get_f_w_i_val   = f_w_i[i_val]
        get_f_w_N2_i    = f_w_i[(N // 2) + i_val]
        get_f_star_w_2i = f_star_w_2i[i_val]
        ABC_proof = listToString([get_f_w_i_val, get_f_w_N2_i, get_f_star_w_2i])

        if ti == "0":
            auth_path_for_ti = mt_fw.getAuthenticationPath(Node.hash(str(f_w_i[i_val])), i_val)
        else:
            auth_path_for_ti = mt_fstar.getAuthenticationPath(Node.hash(str(f_star_w_2i[i_val])), i_val)

        T3 = get_timestamp()
        proof = ABC_proof + "&" + str(auth_path_for_ti) + "&" + R_auth + "&" + str(T3)
        SecureFrame.send_encrypted_frame(client_sock, key, proof.encode())

        VIDnew_Auth_status_S_auth, _ = SecureFrame.recv_encrypted_frame(client_sock, key)
        if VIDnew_Auth_status_S_auth is None: return 'F'
        parts = VIDnew_Auth_status_S_auth.decode().split('&')
        if len(parts) >= 2 and parts[1] == "S":
            return 'S'
    return 'F'

class McElieceSPHINCSServer:
    def __init__(self, host, port,
                 kem_alg="Classic-McEliece-348864",
                 sig_alg="SPHINCS+-SHA2-128s-simple"):
        self.host = host
        self.port = port
        self.kem_alg = kem_alg
        self.sig_alg = sig_alg
        self.server_version = "1.0.3"

    def handle_client(self, client_sock, client_addr):
        print(f"[server] Client connected: {client_addr}")
        try:
            # --- Handshake (cert + encapsulation) ---
            start = time.time()
            kem_mgr = KEMManager(self.kem_alg)
            kem_pub, kem_mgr = kem_mgr.generate_keypair()

            sig_mgr = SignatureManager(self.sig_alg)
            sig_pub, sig_mgr = sig_mgr.generate_keypair()

            cert = Certificate.create_cert(kem_pub, sig_pub, sig_mgr)
            client_sock.send(PQCrypto.write_u32_be(len(cert)))
            SecureFrame.send_all(client_sock, cert)

            ct_len = PQCrypto.read_u32_be(SecureFrame.recv_all(client_sock, 4))
            ciphertext = SecureFrame.recv_all(client_sock, ct_len)
            shared_secret = kem_mgr.decapsulate(ciphertext)

            salt = b"server-salt-v1"
            info = b"mce-sphincs-handshake-v1"
            aes_key = PQCrypto.hkdf_sha256(shared_secret, salt, info, 32)
            shared_secret = bytearray(shared_secret); PQCrypto.secure_clear(shared_secret)

            htime = time.time() - start
            print(f"[server] Secure handshake completed in {htime:.4f}s\n")
            li.append(htime)

            self.command_loop(client_sock, aes_key)

        except Exception as e:
            print(f"[server] Error: {e}")
        finally:
            try: client_sock.close()
            except: pass
            print(f"[server] Client {client_addr} disconnected\n")

    def command_loop(self, client_sock, key):
        while True:
            plaintext, _ = SecureFrame.recv_encrypted_frame(client_sock, key)
            if plaintext is None: break
            if len(plaintext) == 0: continue

            cmd = plaintext.decode('utf-8')
            print(f"[server] Received command: {cmd}")

            if cmd == "close":
                SecureFrame.send_encrypted_frame(client_sock, key, b"Closing connection...\n")
                break
            elif cmd == "check":
                SecureFrame.send_encrypted_frame(client_sock, key, self.server_version.encode())
            elif cmd.startswith("get "):
                version = cmd[4:]
                self.handle_file_download(client_sock, key, version)
            else:
                SecureFrame.send_encrypted_frame(client_sock, key, b"Invalid command\n")

    def handle_file_download(self, client_sock, key, version):
        start = time.time()
        if zkp_verifier(client_sock, key) != 'S':
            print("[server] Zero-Knowledge Proof failed")
            SecureFrame.send_encrypted_frame(client_sock, key, b"NO")
            return

        zkp_t = time.time() - start
        print(f"[server] Zero-Knowledge Proof succeeded in {zkp_t:.4f}s")
        li.append(zkp_t)
        SecureFrame.send_encrypted_frame(client_sock, key, b"YES")

        filename = f"update_{version}.exe"
        start = time.time()
        enc_agg = 0.0
        try:
            with open(filename, 'rb') as f:
                enc_agg += SecureFrame.send_encrypted_frame(client_sock, key, b"OK")
                chunk = f.read(4096)
                while chunk:
                    enc_agg += SecureFrame.send_encrypted_frame(client_sock, key, chunk)
                    chunk = f.read(4096)
                SecureFrame.send_encrypted_frame(client_sock, key, b"")  # EOF

            xfer_t = time.time() - start
            print(f"[server] File transfer completed in {xfer_t:.4f}s")
            print(f"[server] Total encryption time: {enc_agg:.4f}s")
            li.append(xfer_t); li.append(enc_agg); fw.writerow(li); li.clear()
        except FileNotFoundError:
            print(f"[server] File not found: {filename}")
            SecureFrame.send_encrypted_frame(client_sock, key, b"NO")

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, self.port))
            s.listen(16)
            print(f"[server] Listening on {self.host}:{self.port}")
            while True:
                c, addr = s.accept()
                t = threading.Thread(target=self.handle_client, args=(c, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\n[server] Shutting down...")
        finally:
            s.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)
    server = McElieceSPHINCSServer(get_ip(), int(sys.argv[1]))
    server.start()
    f.close()
