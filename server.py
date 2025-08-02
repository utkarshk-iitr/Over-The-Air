#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import os
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def create_https_server():
    server_ip = get_local_ip()
    
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        cert_command = f"""openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
            -subj '/CN={server_ip}' \
            -addext 'subjectAltName=DNS:localhost,IP:{server_ip},IP:127.0.0.1'"""
        os.system(cert_command)
    
    server_address = ('0.0.0.0', 8443)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    
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
