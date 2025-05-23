# Fabric Blockchain API Testing Guide

This document provides guidance on how to test the Hyperledger Fabric blockchain API using the provided Postman collection.

## Prerequisites

1. The Fabric blockchain application is running
2. SoftHSM2 is properly configured
3. Postman is installed (or the Postman VS Code extension is active)

## Setup

1. Import the following files into Postman:
   - `Fabric-Blockchain-API.postman_collection.json` - Contains all API requests
   - `Fabric-Blockchain-Environment.postman_environment.json` - Contains environment variables

2. Select the "Fabric Blockchain Environment" environment in Postman

## Test Sequence

Follow this sequence to properly test the API:

### 1. Register Admin

First, register an admin user:

1. Send the "Register Admin" request
2. From the response, copy the `userId` value
3. Set it as the `adminId` environment variable in Postman

### 2. Register User

Next, register a client user:

1. Send the "Register User" request (a random UUID will be generated automatically)
2. From the response, copy the `userId` value
3. Set it as the `userId` environment variable in Postman

### 3. Submit Transaction

Now you can submit transactions to the blockchain:

1. Ensure the `userId` environment variable is set
2. Send the "Submit Transaction" request with the appropriate transaction data
3. Verify the successful response

### 4. Query Blockchain

Finally, query the blockchain:

1. Ensure the `userId` environment variable is set
2. Send the "Query Blockchain" request with the appropriate query parameters
3. Examine the returned data from the blockchain

## Request Details

### Register Admin
- **Endpoint:** POST `/api/v1/blockchain/admin/register`
- **Description:** Creates a new admin user with a randomly generated UUID
- **Response:** Contains admin credentials and certificate information

### Register User
- **Endpoint:** POST `/api/v1/blockchain/users/register`
- **Body:**
```json
{
    "userId": "{{$guid}}",
    "role": "client",
    "attributes": "organization=Org1"
}
```
- **Response:** Contains user credentials and certificate information

### Submit Transaction
- **Endpoint:** POST `/api/v1/blockchain/transactions`
- **Headers:** 
  - `User-ID`: UUID of a registered user
- **Body:**
```json
{
    "functionName": "createAsset",
    "arguments": ["asset1", "blue", "5", "owner1", "100"],
    "transactionType": "invoke"
}
```
- **Response:** Contains transaction ID and status

### Query Blockchain
- **Endpoint:** POST `/api/v1/blockchain/query`
- **Headers:** 
  - `User-ID`: UUID of a registered user
- **Body:**
```json
{
    "functionName": "readAsset",
    "arguments": ["asset1"],
    "transactionType": "query"
}
```
- **Response:** Contains query result data

## Troubleshooting

- **401 Unauthorized**: Ensure the User-ID header contains a valid UUID that was previously registered
- **400 Bad Request**: Check the request body format and ensure all required fields are present
- **500 Internal Server Error**: Check the application logs for details on server-side issues, particularly related to HSM or blockchain connectivity
