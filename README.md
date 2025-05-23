# Fabric Blockchain Sample

A Java Spring Boot application demonstrating integration with Hyperledger Fabric blockchain network using Hardware Security Module (HSM) for enhanced security.

## Features

- Secure key management using Hardware Security Module (HSM) integration
- Admin and user registration with certificate-based authentication
- REST API for interacting with Fabric chaincode
- Certificate Authority (CA) operations for identity management
- Transaction submission and query capabilities

## Prerequisites

- Java 11 or later
- Gradle 6.5+
- Docker and Docker Compose
- Hyperledger Fabric v2.2+ network setup
- SoftHSM or a hardware HSM device

## Project Structure

```
fabric-blockchain-sample/
├── src/                          # Source code
│   ├── main/java                 # Java source files
│   │   └── com/example/blockchain
│   │       ├── api/              # REST API controllers
│   │       ├── config/           # Application configuration
│   │       ├── exception/        # Custom exceptions
│   │       ├── service/          # Business logic services
│   │       └── util/             # Utility classes
│   └── resources/                # Application resources
│       └── application.yml       # Application configuration
├── creds/                        # Credentials storage (gitignored)
│   ├── certs/                    # Certificate storage
│   └── keys/                     # Key storage (HSM-backed)
├── org1.example.com/             # Fabric organization files
├── build/                        # Build output directory
├── gradle/                       # Gradle wrapper
├── Dockerfile                    # Docker build definition
├── build.gradle                  # Gradle build configuration
└── run-with-hsm.sh              # Script to run with HSM
```

## Setup and Installation

### 1. Configure Environment

Ensure you have the necessary Fabric certificates and connection profiles in the `org1.example.com` directory.

### 2. Configure HSM

Set up your Hardware Security Module:

```bash
# If using SoftHSM
softhsm2-util --init-token --slot 0 --label "FabricHSM" --pin 1234
```

### 3. Build the Application

```bash
./gradlew clean build
```

### 4. Run the Application

```bash
# Using HSM
./run-with-hsm.sh

# Without HSM (for development)
./gradlew bootRun
```

## API Usage

The application exposes a REST API for blockchain operations. Refer to the `API-TESTING-GUIDE.md` or import the Postman collection `Fabric-Blockchain-API.postman_collection.json` for detailed API documentation.

### Key Endpoints

- **POST /api/admin/register** - Register a new admin user
- **POST /api/users/register** - Register a new regular user
- **POST /api/transactions** - Submit a blockchain transaction
- **GET /api/transactions/{txId}** - Query a transaction by ID

## Security Features

- Private keys are generated and stored exclusively in HSM
- Certificate-based authentication for all blockchain operations
- Double-checked locking pattern for admin credential management
- Secure enrollment with Certificate Signing Requests (CSR)

## Testing

Run the automated tests:

```bash
./gradlew test
```

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

## License

This project is licensed under the [MIT License](LICENSE).

