import socket
import threading

import socket
import threading

curr_version = "1.0.0"
avlb_version = "1.0.0"

def menu():
    print("\n"+"-" * 50)
    print("Welcome to the Car Update Server!")
    print("1. Check for updates")
    print("2. Download updates")
    print("3. Install updates")
    print("4. Exit")
    
    choice = input("Enter your choice: ")    
    return choice

def get_curr_ver():
    """Simulate fetching current version from the car's system."""

def install_update():
    """Simulate installing the update."""

def receive_messages(client_socket):
    try:
        message = client_socket.recv(1024).decode('utf-8')
        if message: 
            return message
        else: 
            return None
    except Exception as e:
        print(f"[ERROR] Error receiving message: {e}")
        return None

def check_for_update(client_socket):
    global avlb_version
    client_socket.send("check".encode('utf-8'))
    avlb_version = receive_messages(client_socket)
    print("Current version:", curr_version)
    print("Server has version:",avlb_version)

def get_exe(client_socket):
    msg = "download:"+avlb_version
    client_socket.send(msg.encode('utf-8'))
    print("\n[INFO] Receiving from server...")

    with open(f"car_update_{avlb_version}.exe","wb") as f:
        while True:
            chunk = client_socket.recv(4096)
            if not chunk: 
                break
            f.write(chunk)

    print("File downloaded successfully")

def start_client():
    server_ip = input("Enter server IP address: ").strip()
    
    while True:
        try:
            server_port = int(input("Enter server port: "))
            break
        except ValueError:
            print("Please enter a valid port number")
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(30)  # Set 30 second timeout
    
    try:
        print(f"\nConnecting to {server_ip}:{server_port}...")
        client_socket.connect((server_ip, server_port))
        print(f"Connected successfully!")
        
        # Remove the problematic background thread
        # receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
        # receive_thread.daemon = True
        # receive_thread.start()

        get_curr_ver()

        while True:
            choice = menu()
            if choice == '1':
                check_for_update(client_socket)
            elif choice == '2':
                get_curr_ver()
                if curr_version == avlb_version:
                    print("You are already on the latest version.")
                else:
                    get_exe(client_socket)
                    break  # Close connection after file download
            elif choice == '3':
                print("Installing updates...")
                install_update()
                print("Update installed successfully!")
                curr_version = avlb_version
            elif choice == '4':
                break
            else:
                print("Invalid choice, please try again.")
        
    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to {server_ip}:{server_port}")
        print("Make sure the server is running and the IP/port are correct")
    except socket.timeout:
        print("[ERROR] Connection timed out")
    except Exception as e:
        print(f"[ERROR] Client error: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    start_client()
