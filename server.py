import socket
import threading

srvr_version = "1.0.3"

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def get_srvr_ver():
    """Simulate fetching server version."""


def handle_client(client_socket, address):
    print(f"\n[INFO] Client connection from {address}")
    
    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            
            if message=="check":
                print(f"[INFO] Client requested current server version.")
                get_srvr_ver()
                client_socket.send(f"{srvr_version}".encode('utf-8'))

            elif message.startswith("download:"):
                version = message.split(":")[1]
                print(f"[INFO] Client requested download for version {version}")
                exe = open(f"update_{version}.exe","rb").read()
                client_socket.sendall(exe)
                client_socket.shutdown(socket.SHUT_WR)
                print("[INFO] File sent successfully")

    except Exception as e:
        print(f"[ERROR] Error handling client {address}: {e}")
    finally:
        print(f"[INFO] Closing connection from {address}")
        client_socket.close()

def start_server():
    while True:
        try:
            port = int(input("Enter port number to run server on: "))
            if 1024 <= port <= 65535:
                break
            else:
                print("Please enter a port between 1024 and 65535")
        except ValueError:
            print("Please enter a valid port number")
    
    host = get_local_ip()
    server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(10)
        print(f"\nServer started on {host}:{port}")
        print("Press Ctrl+C to stop the server")
        
        while True:
            client_socket, address = server_socket.accept()
            car_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, address)
            )
            car_thread.daemon = True
            car_thread.start()
            
    except KeyboardInterrupt:
        print("\n[INFO] Server shutting down...")
    except Exception as e:
        print(f"[ERROR] Server error: {e}")
    finally:
        server_socket.close()


start_server()
