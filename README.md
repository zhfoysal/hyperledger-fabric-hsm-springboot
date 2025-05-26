# Hyperledger Fabric HSM SpringBoot Integration

A comprehensive Java Spring Boot application demonstrating enterprise-grade integration with Hyperledger Fabric blockchain network using Hardware Security Module (HSM) for enhanced security and key protection. This project serves as a production-ready reference implementation for organizations looking to build secure blockchain applications with cryptographic key protection.

## Project Purpose

This project demonstrates how to build a secure, enterprise-grade application that interacts with Hyperledger Fabric while protecting cryptographic keys using Hardware Security Module (HSM) technology. It addresses several critical concerns for organizations deploying blockchain solutions:

1. **Security & Compliance**: Demonstrates PKCS#11 integration with HSM for secure key storage, meeting regulatory requirements for financial and sensitive operations.

2. **Identity Management**: Implements comprehensive user and admin identity lifecycle management through Fabric CA, including registration, enrollment, and certificate revocation.

3. **Enterprise Integration**: Provides a production-ready RESTful API that can be integrated into existing enterprise applications and systems.

4. **Extensibility**: Built with a modular architecture that can be extended to support additional blockchain use cases and custom business logic.

5. **Operational Model**: Includes configuration externalization through application.yml, allowing for deployment across different environments without code changes.

## Key Features

- **HSM Integration**: Secure key management using Hardware Security Module (HSM) through PKCS#11 standard
- **Certificate-Based Identity**: Admin and user registration with certificate-based authentication and authorization
- **RESTful API**: Comprehensive API for interacting with Fabric chaincode and network operations
- **CA Integration**: Complete Certificate Authority (CA) operations for identity management
- **Transaction Handling**: Secure transaction submission, endorsement, and query capabilities
- **Configurable Settings**: Externalized configuration for all connection parameters, cryptographic settings, and network elements

## Prerequisites

- Java 11 or later
- Gradle 6.5+
- Docker and Docker Compose
- Hyperledger Fabric v2.2+ network setup
- SoftHSM or a hardware HSM device

## Project Structure

```
hyperledger-fabric-hsm-springboot/
├── src/                          # Source code
│   ├── main/java                 # Java source files
│   │   └── com/example/blockchain
│   │       ├── api/              # REST API controllers and DTOs
│   │       │   ├── controller/   # REST endpoint controllers
│   │       │   └── dto/          # Data transfer objects and responses
│   │       ├── config/           # Application configuration
│   │       │   ├── FabricConfig.java    # Fabric network connectivity
│   │       │   ├── HsmConfig.java       # HSM integration setup
│   │       │   └── SecurityConfig.java  # API security settings
│   │       ├── exception/        # Custom exceptions and error handling
│   │       ├── service/          # Business logic implementation
│   │       │   ├── AdminService.java    # Admin identity operations
│   │       │   ├── UserService.java     # User management
│   │       │   └── TransactionService.java  # Blockchain transactions
│   │       └── util/             # Utility classes for cryptography and helpers
│   └── resources/                # Application resources
│       └── application.yml       # Externalized configuration
├── creds/                        # Credentials storage (gitignored)
│   ├── certs/                    # Certificate storage
│   │   └── *.pem                 # PEM-encoded certificates
│   ├── keys/                     # Key storage (HSM-backed)
│   │   └── *.pem                 # PEM-encoded public keys
│   └── csrs/                     # Certificate signing requests
├── org1.example.com/             # Fabric organization files and connection profiles
├── build/                        # Build output directory
├── gradle/                       # Gradle wrapper
├── Dockerfile                    # Docker build definition
├── build.gradle                  # Gradle build configuration
├── API-TESTING-GUIDE.md          # Detailed API documentation
├── Fabric-Blockchain-API.postman_collection.json  # Postman API collection
└── run-with-hsm.sh               # Script to run with HSM
```

## Technical Details

### Architecture Overview

This application follows a multi-layered architecture:

1. **API Layer**: RESTful controllers exposing blockchain operations to external systems
2. **Service Layer**: Core business logic implementing blockchain interactions 
3. **Configuration Layer**: HSM and Fabric network connectivity setup
4. **Utility Layer**: Cryptographic operations and helper functions

### Security Implementation

- **HSM Integration**: Uses the PKCS#11 standard through SunPKCS11 provider
- **Identity Model**: X.509 certificates with proper chain of trust through Fabric CA
- **Transaction Security**: Implements Fabric Gateway API with HSM-backed signatures for proposals, transactions and commits
- **Signature Verification**: Enforces canonical signature format to prevent signature malleability attacks

## Setup and Installation

### 1. Configure Environment

Ensure you have the necessary Fabric certificates and connection profiles in the `org1.example.com` directory. The application expects a standard Fabric network setup with at least:

- One organization (Org1) with properly configured MSP
- At least one peer with endorsing capability
- A Fabric CA server for identity management
- A deployed chaincode (default name: "basic")

### 2. Configure HSM

Set up your Hardware Security Module:

```bash
# For SoftHSM (development/testing)
softhsm2-util --init-token --slot 0 --label "ForFabric" --pin 98765432

# For production HSM, follow your vendor's instructions and update the
# HSM configuration in application.yml accordingly
```

### 3. Configure Application

Review and update `application.yml` to match your environment:

```yaml
# Hyperledger Fabric Network Configuration
fabric:
  msp-id: Org1MSP
  channel-name: mychannel
  chaincode-name: basic
  peer-endpoint: localhost:7051
  ca-server-endpoint: https://localhost:7054
  
# HSM Configuration  
hsm:
  name: ForFabric
  library: /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
  slot: 1681257824
  pin: 98765432
```

### 4. Build the Application

```bash
./gradlew clean build
```

### 5. Run the Application

```bash
# Using HSM (recommended for production-like testing)
./run-with-hsm.sh

# Without HSM (for development only, not secure)
./gradlew bootRun
```

## API Usage

The application exposes a comprehensive REST API for blockchain operations. Refer to the `API-TESTING-GUIDE.md` or import the Postman collection `Fabric-Blockchain-API.postman_collection.json` for detailed API documentation.

### Key Endpoints

- **POST /blockchain-api/api/v1/blockchain/admin/register** - Register a new admin with HSM-protected keys
- **POST /blockchain-api/api/v1/blockchain/users/register** - Register a new regular user with HSM-protected keys
- **POST /blockchain-api/api/v1/blockchain/transactions** - Submit a transaction to the blockchain
- **POST /blockchain-api/api/v1/blockchain/query** - Query the blockchain ledger

### API Request Example

**Register a user:**
```json
POST /blockchain-api/api/v1/blockchain/users/register
{
  "userId": "6c46e42e-c5df-46b9-b26c-38d9cda72ca2"
}
```

**Submit a transaction:**
```json
POST /blockchain-api/api/v1/blockchain/transactions
Header: User-ID: 6c46e42e-c5df-46b9-b26c-38d9cda72ca2
{
  "functionName": "CreateAsset",
  "arguments": ["asset1", "blue", "5", "Tom", "100"]
}
```

## Security Features

- **HSM Key Protection**: Private keys are generated and stored exclusively in the HSM, never exposed in memory
- **Certificate-Based Identity**: Strong X.509 certificate-based authentication for all blockchain operations
- **Secure Credential Management**: Double-checked locking pattern for thread-safe admin credential management
- **CSR-based Enrollment**: Secure enrollment using Certificate Signing Requests (CSR) model
- **Signature Normalization**: Implementation of low-S value signature normalization to prevent malleability attacks
- **Configuration Externalization**: All sensitive configuration stored in application.yml, not hardcoded

## Advanced Usage

### Custom Chaincode Integration

To interact with your custom chaincode, modify the chaincode name in `application.yml` and create appropriate transaction request DTOs reflecting your chaincode functions.

### HSM Provider Configuration

For production HSMs, replace the SoftHSM library path with your vendor-specific PKCS#11 library and update the slot configuration and credentials accordingly.

### Fabric Network Integration

The application can connect to any properly configured Fabric network by updating the connection profiles and certificates in the `org1.example.com` directory.

## Testing

Run the automated tests:

```bash
./gradlew test
```

## Production Considerations

For production deployments:

1. Replace SoftHSM with a certified hardware HSM solution
2. Implement proper user authentication and authorization for API access
3. Configure TLS for the API endpoints
4. Set up proper logging and monitoring solutions
5. Consider implementing key rotation policies

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to the [hyperledger-fabric-hsm-springboot](https://github.com/yourusername/hyperledger-fabric-hsm-springboot) repository.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

Or use the clean tests script:

```bash
./clean-tests.sh
```

## Docker Deployment

Build and run as a Docker container:

```bash
docker build -t fabric-blockchain-sample .
docker run -p 8080:8080 --name blockchain-api fabric-blockchain-sample
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

