#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os
import socket
import json

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

class HTTPSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>HTTPS Server Working</h1></body></html>')
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            if self.headers.get('Content-Type') == 'application/json':
                data = json.loads(post_data.decode('utf-8'))
                response_data = {"status": "received", "data": data}
            else:
                response_data = {"status": "received", "bytes": len(post_data)}
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        except Exception as e:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

def create_https_server():
    server_ip = get_local_ip()
    
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        cert_command = f"""openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
            -subj '/CN={server_ip}' \
            -addext 'subjectAltName=DNS:localhost,IP:{server_ip},IP:127.0.0.1'"""
        os.system(cert_command)
    
    server_address = ('0.0.0.0', 8443)
    httpd = HTTPServer(server_address, HTTPSHandler)
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('cert.pem', 'key.pem')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"Server: https://{server_ip}:8443")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()

if __name__ == "__main__":
    create_https_server()
