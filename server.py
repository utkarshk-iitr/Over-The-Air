#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os
import socket
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
import datetime
import hashlib

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

class VersionBasedOTAHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.server_latest_version = "2.1.5"  # Server's latest available version
        super().__init__(*args, **kwargs)
    
    def compare_versions(self, car_version, server_version):
        """Server-side version comparison"""
        def version_tuple(v):
            return tuple(map(int, v.split('.')))
        
        car_tuple = version_tuple(car_version)
        server_tuple = version_tuple(server_version)
        
        if server_tuple > car_tuple:
            return True, f"Update available: {car_version} → {server_version}"
        elif server_tuple == car_tuple:
            return False, f"Car is up to date: {car_version}"
        else:
            return False, f"Car version newer than server: {car_version} > {server_version}"
    
    def load_server_certificate(self):
        try:
            with open('cert.pem', 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        except Exception as e:
            print(f"Failed to load server certificate: {e}")
            return None
    
    def create_update_file(self, from_version, to_version):
        """Create version-specific update file"""
        update_content = f"""#!/bin/bash
# OTA Update: {from_version} → {to_version}
# Generated: {datetime.datetime.now()}
echo "Upgrading from version {from_version} to {to_version}..."
echo "Applying update patches..."
echo "Update installation completed successfully"
echo "Current version: {to_version}"
exit 0
        """.encode('utf-8')
        
        update_filename = f"update_{from_version}_to_{to_version}.exe"
        with open(update_filename, 'wb') as f:
            f.write(update_content)
        
        return update_filename, update_content
    
    def encrypt_response_for_car(self, response_data, car_public_key_pem):
        try:
            car_public_key = serialization.load_pem_public_key(car_public_key_pem.encode('utf-8'))
            
            server_cert = self.load_server_certificate()
            if server_cert:
                response_data['server_certificate'] = server_cert
            
            response_json = json.dumps(response_data)
            
            encrypted_data = car_public_key.encrypt(
                response_json.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            print(f"Encryption failed: {e}")
            return None
    
    def encrypt_file_for_car(self, file_data, car_public_key_pem):
        try:
            car_public_key = serialization.load_pem_public_key(car_public_key_pem.encode('utf-8'))
            
            encrypted_data = car_public_key.encrypt(
                file_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            print(f"File encryption failed: {e}")
            return None
    
    def is_valid_car_request(self, request_data):
        required_fields = ['car_id', 'version', 'public_key']
        return all(field in request_data for field in required_fields)
    
    def do_POST(self):
        if self.path == '/check_update':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode('utf-8'))
                
                print(f"Update check from car: {request_data.get('car_id')}")
                
                if not self.is_valid_car_request(request_data):
                    self.send_response(400)
                    self.end_headers()
                    return
                
                car_id = request_data.get('car_id')
                car_public_key = request_data.get('public_key')
                car_current_version = request_data.get('version')
                
                # Compare versions to determine if update is available
                update_available, version_message = self.compare_versions(
                    car_current_version, self.server_latest_version
                )
                
                print(f"Version check: {version_message}")
                
                response_data = {
                    "status": "OK",
                    "update_available": update_available,
                    "latest_version": self.server_latest_version,
                    "car_version": car_current_version,
                    "car_id": car_id,
                    "version_message": version_message,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                
                encrypted_response = self.encrypt_response_for_car(response_data, car_public_key)
                
                if encrypted_response:
                    final_response = {
                        "encrypted_data": encrypted_response,
                        "encryption_method": "RSA-OAEP-SHA256"
                    }
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(final_response).encode('utf-8'))
                    
                    print(f"Response sent to car {car_id}: Update Available = {update_available}")
                else:
                    self.send_response(500)
                    self.end_headers()
                
            except Exception as e:
                print(f"Check update error: {e}")
                self.send_response(400)
                self.end_headers()
        
        elif self.path == '/download_update':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode('utf-8'))
                
                car_id = request_data.get('car_id')
                car_public_key = request_data.get('public_key')
                current_version = request_data.get('current_version')
                requested_version = request_data.get('requested_version')
                
                print(f"Download request: {car_id} wants {current_version} → {requested_version}")
                
                # Create version-specific update file
                update_filename, update_content = self.create_update_file(
                    current_version, requested_version
                )
                file_hash = hashlib.sha256(update_content).hexdigest()
                
                # Encrypt file for car
                encrypted_file = self.encrypt_file_for_car(update_content, car_public_key)
                
                if encrypted_file:
                    response_data = {
                        "encrypted_file": encrypted_file,
                        "file_hash": file_hash,
                        "filename": update_filename,
                        "from_version": current_version,
                        "to_version": requested_version,
                        "file_size": len(update_content),
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(response_data).encode('utf-8'))
                    
                    print(f"Sent update file to {car_id}: {update_filename}")
                else:
                    self.send_response(500)
                    self.end_headers()
                
            except Exception as e:
                print(f"Download error: {e}")
                self.send_response(400)
                self.end_headers()
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html_content = f"""
            <html>
            <body>
            <h1>OTA Update Server</h1>
            <p>Latest Version: {self.server_latest_version}</p>
            <p>Server Status: Online</p>
            </body>
            </html>
            """.encode('utf-8')
            self.wfile.write(html_content)

def create_version_based_server():
    server_ip = get_local_ip()
    
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        cert_command = f"""openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
            -subj '/CN=CarManufacturer/O=AutoCompany' \
            -addext 'subjectAltName=DNS:localhost,IP:{server_ip},IP:127.0.0.1'"""
        os.system(cert_command)
    
    if not os.path.exists('company_cert.pem'):
        os.system("cp cert.pem company_cert.pem")
    
    server_address = ('0.0.0.0', 8443)
    httpd = HTTPServer(server_address, VersionBasedOTAHandler)
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('cert.pem', 'key.pem')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"OTA Server: https://{server_ip}:8443")
    print(f"Latest Version Available: 2.1.5")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()

if __name__ == "__main__":
    create_version_based_server()
