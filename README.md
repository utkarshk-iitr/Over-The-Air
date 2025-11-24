# Over-The-Air (OTA) Update System

A comprehensive Over-The-Air update management system for deploying firmware and software updates to connected autonomous vehicles.

## Prerequisites

- [liboqs] (https://github.com/open-quantum-safe/liboqs)
- [liboqs-python] (Installs along with liboqs)
- [oqs] (pip install oqs)
- [pyoqs_sdk] (https://github.com/sagarbhure/pyoqs_sdk)

## Running the Project

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Over-The-Air.git
   cd Over-The-Air/PQ
   ```
   
2. **Start the server**
    ```bash
   python3 server_pq.py <Port>
   ```

3. **Run the client**
    ```bash
    python3 client_pq.py <Server IP> <Port>
    ```

Continue with the steps in program