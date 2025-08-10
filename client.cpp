#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cstdint> 
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <bits/stdc++.h>

#define BUFFER_SIZE 4096
#define LGREEN "\033[1;32m"
#define LBLUE "\033[1;34m"
#define RESET "\033[0m"
using namespace std;

void send_command(int sock, string command);
void handle_get(int sock, string filename);

string curr_version="1.0.0", avlb_version="1.0.0";

bool send_all(int sock, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    while (len > 0) {
        int bytes = send(sock, p, len, 0);
        if (bytes <= 0) return false;
        p += bytes;
        len -= bytes;
    }
    return true;
}

bool recv_all(int sock, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
    while (len > 0) {
        int bytes = recv(sock, p, len, 0);
        if (bytes <= 0) return false;
        p += bytes;
        len -= bytes;
    }
    return true;
}

string show_menu(){
    cout << "\n" << string(50, '-') << endl;
    cout << "Welcome to the Car Update Server!" << endl;
    cout << "1. Check for updates" << endl;
    cout << "2. Download updates" << endl;
    cout << "3. Install updates" << endl;
    cout << "4. Exit" << endl;

    string choice;
    cout << "Enter your choice: ";
    getline(cin, choice);
    return choice;
}

void get_curr_version() {
    cout<<"Current version: "<<curr_version<<endl;
}

void get_server_version(int sock) {
    send(sock,"check",5,0);
    char buffer[BUFFER_SIZE];
    recv(sock, buffer, BUFFER_SIZE, 0);
    avlb_version = buffer;
    cout<<"Current version: "<<curr_version<<endl;
    cout << "Available version: " << avlb_version << endl;
}

void handle_install(){
    cout<<"Installing updates..."<<endl;
    curr_version = avlb_version;
}

int main(int argc, char *argv[]){
    if(argc != 3){
        cout << "Usage: ./client <server_ip> <port>" << endl;
        return 1;
    }

    char* SERVER_IP = argv[1];
    int PORT = atoi(argv[2]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1){
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    cout << "Connected to server at " << SERVER_IP << ":" << PORT << endl;
    get_curr_version();

    while (true){
        string command = show_menu();
        if (command.empty())
            continue;

        else if (command == "1"){
            get_server_version(sock);
        }
        else if (command == "2"){
            handle_get(sock, avlb_version);
        }
        else if (command == "3"){
            handle_install();
        }

        else if (command == "4"){
            send_command(sock,"close");
            break;
        }

        else{
            send_command(sock, command);
        }
    }

    close(sock);
    return 0;
}

void send_command(int sock, string command){
    char buffer[BUFFER_SIZE];
    send(sock, command.c_str(), command.size(), 0);
    memset(buffer, 0, BUFFER_SIZE);
    recv(sock, buffer, BUFFER_SIZE, 0);
    cout << buffer;
}

void handle_get(int sock, string filename) {
    string command = "get " + filename;
    filename = "car_update_" + filename + ".exe";

    if(curr_version==avlb_version){
        cout<<"You are using the latest version."<<endl;
        return;
    }
    send(sock, command.c_str(), command.size(), 0);

    char ok[2];
    if (!recv_all(sock, ok, 2) || strncmp(ok, "OK", 2) != 0) {
        cout << "File not found on server or bad response." << endl;
        return;
    }

    ofstream file(filename, ios::binary);
    if (!file) {
        cout << "Local file error" << endl;
        return;
    }

    cout << "Receiving " << filename << " ...\n";

    const uint32_t ERROR_SIGNAL = 0xFFFFFFFF;
    char buffer[BUFFER_SIZE];
    int status = 1;
    
    uint64_t bytes_received = 0;

    while (true) {
        uint32_t net_chunk_size;
        if (!recv_all(sock, &net_chunk_size, sizeof(net_chunk_size))) {
            cout << "Connection lost\n";
            status = 0;
            break;
        }

        uint32_t chunk_size = ntohl(net_chunk_size);

        if (chunk_size == ERROR_SIGNAL) {
            cout << "Server reported error\n";
            status = 0;
            break;
        }

        if (chunk_size == 0) break; // EOF

        if (chunk_size > BUFFER_SIZE) {
            cout << "Received chunk size too big, possible corruption\n";
            status = 0;
            break;
        }

        if (!recv_all(sock, buffer, chunk_size)) {
            cout << "Incomplete chunk received\n";
            status = 0;
            break;
        }

        file.write(buffer, chunk_size);
        if (!file) {
            cout << "File write error\n";
            status = 0;
            break;
        }
        
        bytes_received += chunk_size;
    }

    cout<<"File downloaded successfully\n";
    file.close();
    
}