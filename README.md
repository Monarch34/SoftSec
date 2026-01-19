# SoftSec - Secure Chat Application

A secure UDP-based chat application implementing password hashing and challenge-response authentication.

## Security Features

- 🔐 **PBKDF2-SHA256** password hashing with salt
- 🤝 **Challenge-response** authentication (no password sent over network)
- 🔒 Client-side password hashing before transmission

## Architecture

- **Protocol:** UDP (User Datagram Protocol)
- **Auth Method:** 
  1. Client requests salt from server
  2. Server sends stored salt
  3. Client computes hash locally
  4. Server verifies hash

## Files

| File | Description |
|------|-------------|
| `server.py` | Chat server with user registration and authentication |
| `client.py` | Interactive client with signup/signin flow |

## Usage

```bash
# Start the server
python server.py

# Start a client (in another terminal)
python client.py
```

## Author

[@Monarch34](https://github.com/Monarch34)
