#!/usr/bin/env python3
import http.client
import ssl
import json
import os

class RemoteHTTPSClient:
    def __init__(self, host, port=8443):
        self.host = host
        self.port = port
        self.connection = None
    
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
    
    def get(self, path="/"):
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            self.connection.request("GET", path)
            response = self.connection.getresponse()
            
            return {
                "status": response.status,
                "reason": response.reason,
                "headers": dict(response.getheaders()),
                "body": response.read().decode('utf-8', errors='ignore')
            }
        except Exception as e:
            print(f"GET failed: {e}")
            return None
    
    def post(self, path, data):
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            json_data = json.dumps(data)
            headers = {
                'Content-Type': 'application/json',
                'Content-Length': str(len(json_data))
            }
            
            self.connection.request("POST", path, json_data, headers)
            response = self.connection.getresponse()
            
            return {
                "status": response.status,
                "reason": response.reason,
                "headers": dict(response.getheaders()),
                "body": response.read().decode('utf-8', errors='ignore')
            }
        except Exception as e:
            print(f"POST failed: {e}")
            return None
    
    def upload_file(self, file_path, upload_endpoint="/upload"):
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            headers = {
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(len(file_data)),
                'X-Filename': os.path.basename(file_path)
            }
            
            self.connection.request("POST", upload_endpoint, file_data, headers)
            response = self.connection.getresponse()
            
            return {
                "status": response.status,
                "reason": response.reason,
                "body": response.read().decode('utf-8', errors='ignore')
            }
        except Exception as e:
            print(f"Upload failed: {e}")
            return None
    
    def close(self):
        if self.connection:
            self.connection.close()

def main():
    server_ip = input("Server IP: ").strip()
    if not server_ip:
        return
    
    client = RemoteHTTPSClient(server_ip, 8443)
    
    if client.connect():
        response = client.get("/")
        if response:
            print(f"Status: {response['status']}")
        
        post_data = {"message": "test", "client": "RemoteHTTPSClient"}
        response = client.post("/test", post_data)
        if response:
            print(f"POST Status: {response['status']}")
    
    client.close()

if __name__ == "__main__":
    main()
