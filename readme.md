# AES-256-GCM Encryption Web Service

A secure web-based encryption service implementing AES-256-GCM (Galois/Counter Mode) encryption with a modern user interface. This project demonstrates secure data encryption and decryption using a C++ backend server and JavaScript frontend.

![Demo Screenshot](demo.png)

## Features

- **Strong Encryption**: AES-256-GCM authenticated encryption
- **User-Friendly Interface**: Clean, responsive design with tabs for encryption/decryption
- **Dynamic Key Management**: Support for user-provided keys with random key generator
- **Cross-Platform**: Works on any modern browser
- **Real-Time Feedback**: Instant encryption/decryption results
- **Error Handling**: Comprehensive validation and error reporting
- **Unicode Support**: Handles multiple languages and special characters
- **Base64 Encoding**: Secure handling of binary data

## Quick Start

### Prerequisites
- C++ compiler with C++11 support
- Boost libraries (asio, beast)
- OpenSSL library
- nlohmann/json library

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aes-encryption-service.git
cd aes-encryption-service
```

2. Build the server:
```bash
g++ -o encryption_server api.cpp -lssl -lcrypto -lboost_system -pthread
```

3. Start the server:
```bash
./encryption_server
```

4. Open `index.html` in your browser

## Usage

### Web Interface

#### Encryption
1. Enter a 32-character key or click "Generate Random Key"
2. Input text to encrypt
3. Click "Encrypt"
4. Save the displayed ciphertext, IV, and tag

#### Decryption
1. Enter the same 32-character key
2. Input the ciphertext, IV, and tag
3. Click "Decrypt"
4. View the decrypted text

### API Reference

#### Encrypt Data
```http
POST http://localhost:8080/encrypt
Content-Type: application/json

{
    "plaintext": "Text to encrypt",
    "key": "32-character-key-here"
}
```

Response:
```json
{
    "ciphertext": "base64_encoded_ciphertext",
    "iv": "base64_encoded_iv",
    "tag": "base64_encoded_tag"
}
```

#### Decrypt Data
```http
POST http://localhost:8080/decrypt
Content-Type: application/json

{
    "ciphertext": "base64_encoded_ciphertext",
    "iv": "base64_encoded_iv",
    "tag": "base64_encoded_tag",
    "key": "32-character-key-here"
}
```

Response:
```json
{
    "plaintext": "Original text"
}
```

## Example Usage

```javascript
// Complex text example with multiple languages and formats
const testData = `
🌟 Secure Communication Protocol v1.0 🌟

English: The quick brown fox jumps over the lazy dog!
Spanish: El veloz murciélago hindú comía feliz cardillo y kiwi
Japanese: すべての人間は、生まれながらにして自由であり
Chinese: 人人生而自由，在尊严和权利上一律平等

#$%^&* Special Ch@racters !@#$ ™®©
`;

// Structured data example
const jsonData = {
    user: {
        id: "USR123",
        name: "John Doe",
        permissions: ["read", "write"]
    },
    timestamp: "2024-03-20T10:30:00Z"
};
```

## Security Considerations

- Keys must be exactly 32 characters
- Server runs on HTTP (not HTTPS)
- Implements CORS for cross-origin requests
- In-memory processing only
- No persistent storage of keys or data

## Technical Details

### Server (C++)
- Boost.Beast for HTTP server
- OpenSSL for cryptographic operations
- nlohmann/json for JSON parsing
- Base64 encoding/decoding implementation

### Client (JavaScript)
- Fetch API for HTTP requests
- Modern ES6+ features
- Dynamic DOM manipulation
- Error handling and validation

## Development

### Building from Source

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libboost-all-dev libssl-dev nlohmann-json3-dev

# Build
g++ -o encryption_server api.cpp -lssl -lcrypto -lboost_system -pthread
```

### Running Tests

```bash
# Start server
./encryption_server

# Run test suite (if implemented)
./run_tests.sh
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OpenSSL for encryption libraries
- Boost for networking capabilities
- nlohmann/json for JSON handling
- The C++ community for inspiration and support

## Support

For issues and feature requests, please use the [GitHub issue tracker](https://github.com/yourusername/aes-encryption-service/issues).

## Disclaimer

This is a demonstration project intended for educational purposes. For production use, please ensure:
- Implementation of HTTPS
- Proper key management
- Rate limiting
- Input sanitization
- Security auditing
