#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <bits/stdc++.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#define MAX_CLIENTS 8
#define BUFFER_SIZE 4096
#define LGREEN "\033[1;32m"
#define DGREEN "\033[0;32m"
#define LBLUE "\033[1;34m"
#define RED "\033[1;31m"
#define YELLOW "\033[1;33m"
#define CYAN "\033[1;36m"
#define RESET "\033[0m"
using namespace std;

string server_ver = "1.0.3";
void *handle_client(void *client_socket);
string getip(){
    struct ifaddrs *interfaces = nullptr;
    struct ifaddrs *ifa = nullptr;
    if (getifaddrs(&interfaces) == -1) {
        return "-1";
    }
    
    string myip;
    for (ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            // Check if this is a WiFi interface
            // Common WiFi interface names: wlan, wlp, wl, wifi
            string ifname = ifa->ifa_name;
            if (ifname.find("wlan") != string::npos || 
                ifname.find("wlp") != string::npos || 
                ifname.find("wl") != string::npos || 
                ifname.find("wifi") != string::npos) {
            void* addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, addr_ptr, ip, sizeof(ip));
                if (string(ip) != "127.0.0.1") {
                    myip = ip;
                    break;  // Found WiFi IP, no need to continue
                }
            }
        }
    }
    freeifaddrs(interfaces);
    
    // If no WiFi interface found, try to get any non-loopback IPv4 address
    if (myip.empty()) {
        for (ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                void* addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, addr_ptr, ip, sizeof(ip));
                if (string(ip) != "127.0.0.1") {
                    myip = ip;
                    break;
                }
            }
        }
    }
    
    return myip.empty() ? "-1" : myip;
}

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

int main(int argc, char* argv[]){
    if (argc != 2) {
        cerr << "Usage: ./server <port>" <<endl;
        return 1;
    }
    int port = atoi(argv[1]);

    if (port <= 1024 || port > 65535) { 
        cerr << "Please provide a valid port number in the range 1025-65535.\n";
        return 1;
    }

    int server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1){
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        perror("Reuse failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CLIENTS) < 0){
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    string myip = getip();
    if(myip=="-1"){
        cout<<"Error in getting IP"<<endl;
        return 0;
    }
    cout << "Server started at " << myip<<":"<<port << " ...\n"<<endl;

    while (true){
        client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0){
            perror("Client accept failed");
            continue;
        }
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void *)&client_socket);
        pthread_detach(thread_id);
    }

    close(server_fd);
    return 0;
}

void get_srvr_ver(){
    cout<<"[INFO] Current server version: "<<server_ver<<endl;
};

void *handle_client(void *client_socket){
    int sock = *(int *)client_socket;
    char buffer[BUFFER_SIZE];
    string client_directory = ".";
    cout<<LGREEN<<"Clients connected"<<RESET<<endl<<endl;

    while (true){
        char actualpath[PATH_MAX];
            if (realpath(client_directory.c_str(), actualpath) != NULL) {
                string response = string(actualpath);
                client_directory = response;
            }
            else{
                continue;
            }
        memset(buffer, 0, BUFFER_SIZE);
        if (recv(sock, buffer, BUFFER_SIZE, 0) <= 0){
            cout << LBLUE<<"Client disconnected.\n";
            pthread_exit(NULL);
        }

        string command(buffer);
        command = command.substr(0, command.find("\n"));

        if (command == "check"){
            cout<<"[INFO] Client requested current server version."<<endl;
            get_srvr_ver();
            send(sock,server_ver.c_str(),server_ver.size(),0);
        }

        else if (command.substr(0, 3) == "get") {
            string filename = "update_" + command.substr(4) + ".exe";

            ifstream file(filename, ios::binary);
            if (!file) {
                send(sock,"NO",2,0);
                continue;
            }

            send(sock,"OK",2,0);
            const uint32_t ERROR_SIGNAL = 0xFFFFFFFF;
            char buffer[BUFFER_SIZE];

            cout << "Sending " << filename << " ...\n";

            while (file.read(buffer, BUFFER_SIZE) || file.gcount() > 0) {
                uint32_t chunk_size = file.gcount();
                uint32_t net_chunk_size = htonl(chunk_size);

                if (!send_all(sock, &net_chunk_size, sizeof(net_chunk_size)) || 
                    !send_all(sock, buffer, chunk_size)) {
                    uint32_t net_err = htonl(ERROR_SIGNAL);
                    send_all(sock, &net_err, sizeof(net_err));
                    cout << "Error sending chunk. Aborted.\n";
                    break;
                }
            }

            uint32_t zero = htonl(0);
            send_all(sock, &zero, sizeof(zero));
            file.close();
            cout << "File sent successfully\n" << endl;
        }        
        
        else if (command == "close"){
            cout <<LBLUE<<"Client disconnected.\n"<<RESET;
            send(sock, "Closing connection...\n\n", 23, 0);
            close(sock);
            pthread_exit(NULL);
        }

        else{
            cout<<RED<<"Invalid command: "<<command<<RESET<<endl<<endl;
            send(sock, "Invalid command\n", 16, 0);
        }
    }
}