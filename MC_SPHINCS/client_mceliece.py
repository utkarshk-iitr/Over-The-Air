#!/usr/bin/env python3
"""
Classic McEliece (KEM) + SPHINCS+ (signatures) OTA Client
- Verifies SPHINCS+ signed certificate
- Encapsulates to server's McEliece KEM to derive AES key
- ZKP/Merkle auth then fetches update
"""

import socket, sys, time, csv, random, string
from mceliece_crypto import *
from merkle import *
import pyexcel as pe

f2 = open("client_time.csv", "a", newline="")
fw = csv.writer(f2)
li = []

def zkp_prover(veh_conn, key, VID):
    prime_field = 17; w = 7; N = 16; ID_size = 7
    reg_sheet1 = pe.get_sheet(file_name="FRI_TA_Reg.xlsx")

    SecureFrame.send_encrypted_frame(veh_conn, key, VID.encode())
    Auth_Req_VPR_T1, _ = SecureFrame.recv_encrypted_frame(veh_conn, key)
    if Auth_Req_VPR_T1 is None:
        print("ZKP: failed to receive A1"); return
    A1 = Auth_Req_VPR_T1.decode().split('&')
    if len(A1) != 3:
        print("Unable to fetch vehicle details correctly"); return

    Auth_Req, VPR_star, T1 = A1[0], A1[1], float(A1[2])
    if Auth_Req != "A1" or get_timestamp() - T1 >= 4:
        print("A1 invalid or timed out"); return

    found = 0
    for row in reg_sheet1:
        if row[1] == VPR_star:
            alpha = row[2]; MR_fx = row[4]; MR_fstar = row[5]; found = 1; break
    if not found:
        print("Vehicle not registered"); return

    i_val = random.randint(0, N // 2 - 1)
    ti = random.randint(0, 1)
    R_auth = random.randint(100, 100000)
    T2 = get_timestamp()
    msg2 = f"{ti}&{R_auth}&{i_val}&{T2}"
    SecureFrame.send_encrypted_frame(veh_conn, key, msg2.encode())

    proof_pi_R_auth_T3, _ = SecureFrame.recv_encrypted_frame(veh_conn, key)
    if proof_pi_R_auth_T3 is None:
        print("ZKP: failed to receive proof"); return
    pr = proof_pi_R_auth_T3.decode().split('&')
    ABC = pr[0]; Authpath_ti = eval(pr[1]); R_auth_star = int(pr[2]); T3 = float(pr[3])

    if get_timestamp() - T3 < 4 and R_auth_star == R_auth:
        if ti == 0: merkle_ver_status = Ver_merkle_path(Authpath_ti, MR_fx)
        else:       merkle_ver_status = Ver_merkle_path(Authpath_ti, MR_fstar)
        if merkle_ver_status != 1:
            print("Merkle verification failed"); return

        ABC_list = [int(i) for i in ABC.split(',')]
        y1, y2, y3 = ABC_list[0], ABC_list[1], ABC_list[2]
        w_minus_i_mod_p = pow(w, -i_val, prime_field)
        inv2 = pow(2, -1, prime_field)
        term1 = 1 + int(alpha) * w_minus_i_mod_p
        term2 = 1 - int(alpha) * w_minus_i_mod_p
        y3_calc = ((term1 * y1 + term2 * y2) * inv2) % prime_field
        if y3_calc == y3:
            VIDnew = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(ID_size))
            S_auth = random.randint(100, 10000)
            SecureFrame.send_encrypted_frame(veh_conn, key, f"{VIDnew}&S&{S_auth}".encode())
        else:
            SecureFrame.send_encrypted_frame(veh_conn, key, b"F")

class McElieceSPHINCSClient:
    def __init__(self, host, port,
                 kem_alg="Classic-McEliece-348864",
                 sig_alg="SPHINCS+-SHA2-128s-simple"):
        self.host = host; self.port = port
        self.kem_alg = kem_alg; self.sig_alg = sig_alg
        self.current_version = "1.0.0"
        self.available_version = "1.0.0"
        self.VID = "KAF91EA"

    def connect_and_handshake(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            start = time.time()
            self.sock.connect((self.host, self.port))
            print(f"[client] Connected to {self.host}:{self.port}")

            # Receive certificate
            cert_len = PQCrypto.read_u32_be(SecureFrame.recv_all(self.sock, 4))
            cert = SecureFrame.recv_all(self.sock, cert_len)
            kem_pub, sig_pub, signature = Certificate.parse_cert(cert)

            # Verify SPHINCS+ signature
            message = kem_pub + sig_pub
            if not SignatureManager.verify(self.sig_alg, message, signature, sig_pub):
                raise ValueError("Server certificate signature invalid")
            print(f"[client] Verified SPHINCS+ certificate ({len(cert)} bytes)")

            # Encapsulate to server KEM
            ciphertext, shared_secret = KEMManager.encapsulate(self.kem_alg, kem_pub)
            self.sock.send(PQCrypto.write_u32_be(len(ciphertext)))
            SecureFrame.send_all(self.sock, ciphertext)

            # Derive AES key
            salt = b"server-salt-v1"; info = b"mce-sphincs-handshake-v1"
            self.aes_key = PQCrypto.hkdf_sha256(shared_secret, salt, info, 32)
            shared_secret = bytearray(shared_secret); PQCrypto.secure_clear(shared_secret)

            htime = time.time() - start
            print(f"[client] Secure handshake completed in {htime:.4f}s")
            li.append(htime)
            return True
        except Exception as e:
            print(f"[client] Handshake failed: {e}")
            return False

    def show_menu(self):
        print("\n" + "="*40)
        print("Welcome to the Car Update Server!")
        print("1. Check for updates")
        print("2. Download updates")
        print("3. Install updates")
        print("4. Exit")
        return input("Enter your choice: ").strip()

    def check_updates(self):
        SecureFrame.send_encrypted_frame(self.sock, self.aes_key, b"check")
        resp, _ = SecureFrame.recv_encrypted_frame(self.sock, self.aes_key)
        if resp:
            self.available_version = resp.decode()
            print(f"Current version: {self.current_version}")
            print(f"Available version: {self.available_version}")

    def download_updates(self):
        if self.current_version == self.available_version:
            print("No updates available"); return

        SecureFrame.send_encrypted_frame(self.sock, self.aes_key, f"get {self.available_version}".encode())

        start = time.time()
        zkp_prover(self.sock, self.aes_key, self.VID)
        res, _ = SecureFrame.recv_encrypted_frame(self.sock, self.aes_key)
        if not res or res.decode() != "YES":
            print("[client] Zero-Knowledge Proof failed"); return

        print(f"[client] Zero-Knowledge Proof succeeded in {time.time()-start:.4f}s")
        li.append(time.time() - start)

        ok, _ = SecureFrame.recv_encrypted_frame(self.sock, self.aes_key)
        if (not ok) or ok.decode() != "OK":
            print(f"Server replied: {ok.decode() if ok else 'No response'}"); return

        filename = f"car_update_{self.available_version}.exe"
        print(f"Receiving {filename}...")
        start_dl = time.time()
        dec_agg = 0.0
        try:
            with open(filename, 'wb') as f:
                while True:
                    chunk, t = SecureFrame.recv_encrypted_frame(self.sock, self.aes_key)
                    dec_agg += t
                    if chunk is None:
                        print("Transfer aborted"); break
                    if len(chunk) == 0: break
                    f.write(chunk)

            dl_t = time.time() - start_dl
            print(f"File downloaded successfully in {dl_t:.4f}s")
            print(f"Total decryption time: {dec_agg:.4f}s")
            li.append(dl_t); li.append(dec_agg); fw.writerow(li); li.clear()
        except Exception as e:
            print(f"File download error: {e}")

    def install_updates(self):
        print("[client] Installing update...")
        self.current_version = self.available_version

    def send_command(self, command):
        SecureFrame.send_encrypted_frame(self.sock, self.aes_key, command.encode())
        resp, _ = SecureFrame.recv_encrypted_frame(self.sock, self.aes_key)
        if resp: print(resp.decode())

    def run(self):
        if not self.connect_and_handshake(): return
        try:
            while True:
                c = self.show_menu()
                if c == "1": self.check_updates()
                elif c == "2": self.download_updates()
                elif c == "3": self.install_updates()
                elif c == "4":
                    SecureFrame.send_encrypted_frame(self.sock, self.aes_key, b"close")
                    resp, _ = SecureFrame.recv_encrypted_frame(self.sock, self.aes_key)
                    if resp: print(resp.decode()); break
                else:
                    self.send_command(c)
        except KeyboardInterrupt:
            print("\n[client] Interrupted by user")
        finally:
            try:
                if hasattr(self, "aes_key"):
                    key = bytearray(self.aes_key); PQCrypto.secure_clear(key)
                self.sock.close()
            except: pass

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>"); sys.exit(1)
    client = McElieceSPHINCSClient(sys.argv[1], int(sys.argv[2]))
    client.run()
    f2.close()
