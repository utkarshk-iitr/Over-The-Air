#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os
import socket
import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
import datetime

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

class OTAHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.current_version = "2.1.5"
        self.update_available = True
        super().__init__(*args, **kwargs)
    
    def load_private_key(self):
        with open('private_key.pem', 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    def load_certificate(self):
        with open('cert.pem', 'rb') as f:
            return x509.load_pem_x509_certificate(f.read())
    
    def create_digital_signature(self, data):
        private_key = self.load_private_key()
        signature = private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def do_POST(self):
        if self.path == '/check_update':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode('utf-8'))
                car_id = request_data.get('car_id')
                current_car_version = request_data.get('version')
                
                cert = self.load_certificate()
                cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                
                response_data = {
                    "status": "OK",
                    "update_available": self.update_available,
                    "latest_version": self.current_version,
                    "car_version": current_car_version,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "certificate": cert_pem
                }
                
                response_json = json.dumps(response_data)
                signature = self.create_digital_signature(response_json)
                
                final_response = {
                    "data": response_data,
                    "signature": signature
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(final_response).encode('utf-8'))
                
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error_response = {"error": str(e)}
                self.wfile.write(json.dumps(error_response).encode('utf-8'))
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>OTA Update Server</h1></body></html>')

def generate_keys():
    if not os.path.exists('private_key.pem'):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        with open('private_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        public_key = private_key.public_key()
        with open('public_key.pem', 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def create_ota_server():
    server_ip = get_local_ip()
    
    generate_keys()
    
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        cert_command = f"""openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
            -subj '/CN=OTA-Server/O=CarManufacturer' \
            -addext 'subjectAltName=DNS:localhost,IP:{server_ip},IP:127.0.0.1'"""
        os.system(cert_command)
    
    server_address = ('0.0.0.0', 8443)
    httpd = HTTPServer(server_address, OTAHandler)
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('cert.pem', 'key.pem')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"OTA Server: https://{server_ip}:8443")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()

if __name__ == "__main__":
    create_ota_server()
