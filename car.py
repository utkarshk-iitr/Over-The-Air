#!/usr/bin/env python3
import http.client
import ssl
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import uuid

class CarOTAClient:
    def __init__(self, server_host, port=8443):
        self.host = server_host
        self.port = port
        self.connection = None
        self.car_id = str(uuid.uuid4())
        self.current_version = "2.1.0"
    
    def connect(self):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.connection = http.client.HTTPSConnection(
                self.host, 
                self.port, 
                context=context,
                timeout=15
            )
            
            self.connection.connect()
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def verify_signature(self, data, signature, certificate_pem):
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
            public_key = cert.public_key()
            
            signature_bytes = base64.b64decode(signature)
            
            public_key.verify(
                signature_bytes,
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def validate_certificate(self, certificate_pem):
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
            
            current_time = cert.not_valid_after
            if current_time < cert.not_valid_before:
                return False
            
            subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if "OTA-Server" not in subject:
                return False
                
            return True
        except Exception as e:
            print(f"Certificate validation failed: {e}")
            return False
    
    def check_for_updates(self):
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            update_request = {
                "car_id": self.car_id,
                "version": self.current_version,
                "timestamp": "2025-08-03T00:00:00"
            }
            
            json_data = json.dumps(update_request)
            headers = {
                'Content-Type': 'application/json',
                'Content-Length': str(len(json_data))
            }
            
            self.connection.request("POST", "/check_update", json_data, headers)
            response = self.connection.getresponse()
            
            if response.status == 200:
                response_data = json.loads(response.read().decode('utf-8'))
                
                server_data = response_data.get('data')
                signature = response_data.get('signature')
                certificate = server_data.get('certificate')
                
                if not self.validate_certificate(certificate):
                    print("Certificate validation failed")
                    return None
                
                server_data_json = json.dumps(server_data)
                if not self.verify_signature(server_data_json, signature, certificate):
                    print("Digital signature verification failed")
                    return None
                
                print("Server certificate and signature validated successfully")
                
                return {
                    "status": server_data.get('status'),
                    "update_available": server_data.get('update_available'),
                    "latest_version": server_data.get('latest_version'),
                    "current_version": server_data.get('car_version'),
                    "certificate_valid": True,
                    "signature_valid": True
                }
            else:
                print(f"Server error: {response.status}")
                return None
                
        except Exception as e:
            print(f"Update check failed: {e}")
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
    print(f"Current Version: {car_client.current_version}")
    
    update_info = car_client.check_for_updates()
    
    if update_info:
        print(f"Server Status: {update_info['status']}")
        print(f"Update Available: {update_info['update_available']}")
        print(f"Latest Version: {update_info['latest_version']}")
        print(f"Certificate Valid: {update_info['certificate_valid']}")
        print(f"Signature Valid: {update_info['signature_valid']}")
        
        if update_info['update_available'] and update_info['latest_version'] != update_info['current_version']:
            print("New update available for download")
        else:
            print("Car is up to date")
    
    car_client.close()

if __name__ == "__main__":
    main()
