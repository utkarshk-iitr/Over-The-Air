# Diffie-Hellman (DH) Implementation

This directory contains a simplified Diffie-Hellman key exchange implementation for benchmarking against the existing Post-Quantum (PQ) and RSA implementations.

## Key Features

- **Diffie-Hellman Key Exchange**: Uses 2048-bit DH parameters for key establishment
- **AES-256-GCM Encryption**: Symmetric encryption for secure file transfer
- **ZKP Authentication**: Zero-Knowledge Proof authentication using Merkle trees (same as PQ/RSA)
- **Benchmarking Support**: Comprehensive timing measurements for performance analysis

## Files

- `dh_crypto.py` - Core DH cryptographic functions and secure framing
- `client_dh.py` - DH client implementation for vehicle updates
- `server_dh.py` - DH server implementation for update distribution
- `client_time.csv` - Client-side performance metrics
- `server_time.csv` - Server-side performance metrics
- `update_1.0.3.exe` - Test update file (1MB) for benchmarking

## Usage

### Start the Server
```bash
python3 server_dh.py <port>
```

### Run the Client
```bash
python3 client_dh.py <host> <port>
```

## Benchmarking Metrics

### Client Metrics (client_time.csv)
- **Handshake**: Time for DH key exchange and AES key derivation
- **ZKP**: Zero-Knowledge Proof verification time
- **Transfer Time**: Total file download duration
- **Decrypt Time**: Cumulative AES decryption time

### Server Metrics (server_time.csv)
- **Handshake**: Time for DH key exchange and AES key derivation
- **ZKP**: Zero-Knowledge Proof verification time
- **Transfer Time**: Total file upload duration
- **Encrypt Time**: Cumulative AES encryption time

## Protocol Flow

1. **Connection**: Client connects to server
2. **DH Exchange**: 
   - Server sends DH parameters and public key
   - Client generates keypair using server's parameters
   - Client sends public key to server
   - Both compute shared secret and derive AES key
3. **ZKP Authentication**: Zero-Knowledge Proof verification using Merkle trees
4. **File Transfer**: Encrypted file transfer after successful authentication
5. **Cleanup**: Secure cleanup of cryptographic material

## Performance Characteristics

This implementation is designed to benchmark:
- **DH Key Exchange Overhead**: Compared to PQ (Kyber) and RSA handshakes
- **AES-GCM Performance**: Symmetric encryption efficiency
- **Memory Usage**: DH parameter and key storage requirements
- **Network Efficiency**: Protocol overhead analysis

## Security Notes

- **ZKP Authentication**: Full Zero-Knowledge Proof authentication using Merkle trees
- **Ephemeral Keys**: DH keys are generated per session
- **Forward Secrecy**: Provides perfect forward secrecy unlike RSA key transport
- **Quantum Vulnerability**: DH is vulnerable to quantum attacks (unlike PQ implementation)

## Comparison with Other Implementations

| Feature | DH | PQ (Kyber+Dilithium) | RSA |
|---------|----|--------------------|-----|
| Key Exchange | DH-2048 | Kyber768 | RSA-2048 |
| Authentication | None | ZKP + Dilithium3 | ZKP + RSA-PSS |
| Symmetric Crypto | AES-256-GCM | AES-256-GCM | Direct RSA |
| Forward Secrecy | Yes | Yes | No |
| Quantum Resistant | No | Yes | No |
