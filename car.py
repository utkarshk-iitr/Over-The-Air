#!/usr/bin/env python3
import http.client
import ssl
import json
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
import uuid
import hashlib

class CarOTAClient:
    def __init__(self, server_host, port=8443):
        self.host = server_host
        self.port = port
        self.connection = None
        self.car_id = str(uuid.uuid4())
        self.current_version = "2.1.3"  # Car's installed version
        self.private_key = None
        self.public_key = None
        self.company_cert = None
    
    def compare_versions(self, current, latest):
        """Compare version strings (semantic versioning)"""
        def version_tuple(v):
            return tuple(map(int, v.split('.')))
        
        current_tuple = version_tuple(current)
        latest_tuple = version_tuple(latest)
        
        if latest_tuple > current_tuple:
            return True  # Update available
        else:
            return False  # No update needed
        
    def load_car_keys(self):
        if not os.path.exists(f'car_{self.car_id}_private_key.pem'):
            self.generate_car_keys()
        
        with open(f'car_{self.car_id}_private_key.pem', 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        self.public_key = self.private_key.public_key()
    
    def load_preinstalled_company_certificate(self):
        if os.path.exists('company_cert.pem'):
            with open('company_cert.pem', 'rb') as f:
                self.company_cert = x509.load_pem_x509_certificate(f.read())
            return True
        else:
            print("Preinstalled company certificate not found")
            return False
    
    def generate_car_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        with open(f'car_{self.car_id}_private_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        if not os.path.exists('company_cert.pem'):
            os.system("openssl req -x509 -newkey rsa:2048 -keyout company_private.pem -out company_cert.pem -days 365 -nodes -subj '/CN=CarManufacturer/O=AutoCompany'")
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def decrypt_server_response(self, encrypted_data_b64):
        try:
            encrypted_data = base64.b64decode(encrypted_data_b64)
            
            decrypted_data = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None
    
    def decrypt_file_data(self, encrypted_file_b64):
        try:
            encrypted_data = base64.b64decode(encrypted_file_b64)
            
            decrypted_data = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted_data
        except Exception as e:
            print(f"File decryption failed: {e}")
            return None
    
    def validate_server_certificate(self, received_cert_pem):
        try:
            received_cert = x509.load_pem_x509_certificate(received_cert_pem.encode('utf-8'))
            
            company_fingerprint = self.company_cert.fingerprint(hashes.SHA256())
            received_fingerprint = received_cert.fingerprint(hashes.SHA256())
            
            if company_fingerprint == received_fingerprint:
                print("Certificate validation: PASSED")
                return True
            else:
                print("Certificate validation: FAILED")
                return False
                
        except Exception as e:
            print(f"Certificate validation failed: {e}")
            return False
    
    def connect(self):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.connection = http.client.HTTPSConnection(
                self.host, 
                self.port, 
                context=context,
                timeout=30
            )
            
            self.connection.connect()
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def check_for_updates(self):
        if not self.connection:
            if not self.connect():
                return None
        
        self.load_car_keys()
        
        if not self.load_preinstalled_company_certificate():
            return None
        
        try:
            update_request = {
                "car_id": self.car_id,
                "version": self.current_version,
                "public_key": self.get_public_key_pem(),
                "timestamp": "2025-08-03T00:00:00",
                "manufacturer": "AutoCompany"
            }
            
            json_data = json.dumps(update_request)
            headers = {
                'Content-Type': 'application/json',
                'Content-Length': str(len(json_data)),
                'X-Car-ID': self.car_id
            }
            
            print(f"Checking for updates... Current version: {self.current_version}")
            self.connection.request("POST", "/check_update", json_data, headers)
            response = self.connection.getresponse()
            
            if response.status == 200:
                response_data = json.loads(response.read().decode('utf-8'))
                encrypted_response = response_data.get('encrypted_data')
                
                if encrypted_response:
                    decrypted_data = self.decrypt_server_response(encrypted_response)
                    
                    if decrypted_data:
                        server_certificate = decrypted_data.get('server_certificate')
                        if server_certificate and self.validate_server_certificate(server_certificate):
                            
                            server_latest_version = decrypted_data.get('latest_version')
                            print(f"Server latest version: {server_latest_version}")
                            
                            # Client-side version comparison
                            update_needed = self.compare_versions(self.current_version, server_latest_version)
                            
                            if update_needed:
                                print(f"Update available: {self.current_version} → {server_latest_version}")
                                return self.download_update(server_latest_version)
                            else:
                                print(f"Car is up to date (Current: {self.current_version}, Latest: {server_latest_version})")
                                return {
                                    "status": "UP_TO_DATE",
                                    "current_version": self.current_version,
                                    "latest_version": server_latest_version,
                                    "update_needed": False
                                }
                        else:
                            print("Certificate validation failed")
                            return None
                    else:
                        return None
                else:
                    return None
            else:
                print(f"Server error: {response.status}")
                return None
                
        except Exception as e:
            print(f"Update check failed: {e}")
            return None
    
    def download_update(self, version):
        try:
            download_request = {
                "car_id": self.car_id,
                "public_key": self.get_public_key_pem(),
                "requested_version": version,
                "current_version": self.current_version,
                "timestamp": "2025-08-03T00:00:00"
            }
            
            json_data = json.dumps(download_request)
            headers = {
                'Content-Type': 'application/json',
                'Content-Length': str(len(json_data)),
                'X-Car-ID': self.car_id
            }
            
            print(f"Downloading update: {self.current_version} → {version}")
            self.connection.request("POST", "/download_update", json_data, headers)
            response = self.connection.getresponse()
            
            if response.status == 200:
                response_data = json.loads(response.read().decode('utf-8'))
                encrypted_file = response_data.get('encrypted_file')
                file_hash = response_data.get('file_hash')
                
                if encrypted_file:
                    print("Decrypting update file...")
                    decrypted_file = self.decrypt_file_data(encrypted_file)
                    
                    if decrypted_file:
                        calculated_hash = hashlib.sha256(decrypted_file).hexdigest()
                        if calculated_hash == file_hash:
                            update_filename = f"update_{self.current_version}_to_{version}.exe"
                            with open(update_filename, 'wb') as f:
                                f.write(decrypted_file)
                            
                            print(f"Update downloaded: {update_filename}")
                            print(f"File size: {len(decrypted_file)} bytes")
                            
                            return {
                                "status": "DOWNLOADED",
                                "filename": update_filename,
                                "from_version": self.current_version,
                                "to_version": version,
                                "file_size": len(decrypted_file)
                            }
                        else:
                            print("File integrity check failed")
                            return None
                    else:
                        return None
                else:
                    return None
            else:
                print(f"Download failed: {response.status}")
                return None
                
        except Exception as e:
            print(f"Download failed: {e}")
            return None
    
    def close(self):
        if self.connection:
            self.connection.close()

def main():
    server_ip = input("OTA Server IP: ").strip()
    if not server_ip:
        return
    
    car_client = CarOTAClient(server_ip, 8443)
    
    print(f"Car ID: {car_client.car_id}")
    print(f"Installed Version: {car_client.current_version}")
    
    result = car_client.check_for_updates()
    
    if result:
        if result.get('status') == 'DOWNLOADED':
            print("Update downloaded successfully!")
            print(f"Upgrade: {result['from_version']} → {result['to_version']}")
            print(f"File: {result['filename']}")
        elif result.get('status') == 'UP_TO_DATE':
            print("No update needed - car is already running the latest version")
        else:
            print(f"Status: {result.get('status')}")
    
    car_client.close()

if __name__ == "__main__":
    main()
