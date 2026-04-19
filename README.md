# SecureVault – Encrypted File Sharing System

SecureVault is a secure file sharing system designed to protect data through encryption and structured key management. The application enables users to upload, store, and retrieve files while ensuring that all sensitive data remains encrypted and accessible only to authorized users.

## Features

- Public-key cryptography for secure key exchange  
- End-to-end file encryption before storage  
- User authentication with hashed passwords (bcrypt)  
- Secure vault-based file and key storage  
- Modular backend architecture using FastAPI  
- Persistent storage support for cloud deployment  

## System Architecture

The project is organized into three main components:

### Backend
Handles authentication, encryption, file operations, and API routing using FastAPI.

### Vault Storage
Stores encrypted files, private keys, and database files in a secure directory structure.

### Frontend
Provides a basic HTML interface to interact with backend APIs.

## Security

- Passwords are hashed using bcrypt  
- Files are encrypted before being stored  
- Private keys are securely managed within the vault  
- Public-key infrastructure ensures safe data exchange  

## Tech Stack

- Python (FastAPI, Uvicorn)  
- Cryptography libraries  
- SQLite  
- HTML  
- Railway (deployment)  

## Deployment

The application is deployed using Railway with a persistent volume mounted to retain user data and keys across deployments.

## Use Cases

- Secure file transfer systems  
- Privacy-focused storage solutions  
- Educational projects in cybersecurity and backend development  

## Author

Vrinda Gupta  
