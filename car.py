import http.client
import ssl
import os
import json

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
            print(f"Connected to remote server {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            print(f"Make sure server at {self.host}:{self.port} is running and reachable")
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
            print(f"GET request failed: {e}")
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
            print(f"POST request failed: {e}")
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
            print(f"File upload failed: {e}")
            return None
    
    def close(self):
        if self.connection:
            self.connection.close()
            print("Connection closed")

def main():
    print("Remote HTTPS Client Demo\n")
    
    server_ip = input("Enter server IP address : ").strip()
    if not server_ip:
        print("No IP address provided")
        return
    
    print(f"Connecting to remote HTTPS server at {server_ip}...")
    client = RemoteHTTPSClient(server_ip, 8443)
    if client.connect():
        print("\nMaking GET request...")
        response = client.get("/")
        if response:
            print(f"Status: {response['status']} {response['reason']}")
            print(f"Response length: {len(response['body'])} characters")
            print("First 200 characters:", response['body'][:200])
        
        print("\nMaking POST request...")
        post_data = {
            "message": "Hello from remote client!",
            "client_info": "RemoteHTTPSClient",
            "timestamp": "2025-01-01"
        }
        response = client.post("/test", post_data)
        if response:
            print(f"POST Status: {response['status']} {response['reason']}")
    
    client.close()

main()
