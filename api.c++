#include <iostream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>

using namespace boost::asio;
using namespace boost::beast;
using json = nlohmann::json;

constexpr int AES_KEY_SIZE = 32; // 256-bit key
constexpr int AES_IV_SIZE = 12;  // GCM standard IV size
constexpr int TAG_SIZE = 16;     // GCM authentication tag

// Forward declarations
std::string base64_encode(const unsigned char* bytes, size_t len);
std::string base64_encode(const std::string& str);
std::string base64_encode(const std::vector<unsigned char>& bytes);
std::vector<unsigned char> base64_decode(const std::string& encoded_string);

// Generate random IV
std::vector<unsigned char> generateIV() {
    std::vector<unsigned char> iv(AES_IV_SIZE);
    RAND_bytes(iv.data(), AES_IV_SIZE);
    return iv;
}

// AES-256-GCM Encryption
std::string encryptAES(const std::string& plaintext, const std::vector<unsigned char>& key, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    return std::string(ciphertext.begin(), ciphertext.end());
}

// AES-256-GCM Decryption
std::string decryptAES(const std::string& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.data(), ciphertext.size());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag.data());

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: Authentication failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

// HTTP Request Handler
void handle_request(http::request<http::string_body> req, http::response<http::string_body>& res) {
    std::cout << "\n=== New Request ===" << std::endl;
    std::cout << "Method: " << req.method_string() << std::endl;
    std::cout << "Target: " << req.target() << std::endl;

    // Handle OPTIONS request for CORS preflight
    if (req.method() == http::verb::options) {
        res.result(http::status::ok);
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "POST, GET, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");
        return;
    }

    std::cout << "Body: " << req.body() << std::endl;

    try {
        json request_json = json::parse(req.body());
        
        if (req.target() == "/encrypt") {
            if (!request_json.contains("plaintext") || !request_json.contains("key")) {
                throw std::runtime_error("Missing 'plaintext' or 'key' field in request");
            }

            // Convert key to bytes and validate length
            std::string key_str = request_json["key"];
            std::vector<unsigned char> key(key_str.begin(), key_str.end());
            if (key.size() != AES_KEY_SIZE) {
                throw std::runtime_error("Key must be exactly 32 bytes (256 bits)");
            }

            std::vector<unsigned char> iv = generateIV();
            std::vector<unsigned char> tag(TAG_SIZE);
            std::string ciphertext = encryptAES(request_json["plaintext"], key, iv, tag);

            json response_json = {
                {"ciphertext", base64_encode(ciphertext)},
                {"iv", base64_encode(iv)},
                {"tag", base64_encode(tag)}
            };
            
            std::cout << "Encryption successful" << std::endl;
            res.result(http::status::ok);
            res.body() = response_json.dump(4);
        } 
        else if (req.target() == "/decrypt") {
            if (!request_json.contains("ciphertext") || !request_json.contains("iv") || 
                !request_json.contains("tag") || !request_json.contains("key")) {
                throw std::runtime_error("Missing required fields (ciphertext, iv, tag, or key)");
            }

            // Convert key to bytes and validate length
            std::string key_str = request_json["key"];
            std::vector<unsigned char> key(key_str.begin(), key_str.end());
            if (key.size() != AES_KEY_SIZE) {
                throw std::runtime_error("Key must be exactly 32 bytes (256 bits)");
            }

            std::string ciphertext_str(base64_decode(request_json["ciphertext"]).begin(), 
                                      base64_decode(request_json["ciphertext"]).end());
            std::vector<unsigned char> iv = base64_decode(request_json["iv"]);
            std::vector<unsigned char> tag = base64_decode(request_json["tag"]);

            std::string plaintext = decryptAES(ciphertext_str, key, iv, tag);
            
            json response_json = {{"plaintext", plaintext}};
            std::cout << "Decryption successful" << std::endl;
            res.result(http::status::ok);
            res.body() = response_json.dump(4);
        } 
        else {
            res.result(http::status::not_found);
            res.body() = "Invalid endpoint. Use /encrypt or /decrypt";
            std::cout << "Invalid endpoint requested" << std::endl;
        }

        // Set response headers
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "POST, GET, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");
        res.set(http::field::content_type, "application/json");
        res.set(http::field::server, "AES-GCM Encryption Server");
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        res.result(http::status::bad_request);
        res.body() = json{{"error", e.what()}}.dump(4);
        res.set(http::field::content_type, "application/json");
    }

    std::cout << "Response status: " << res.result_int() << std::endl;
    std::cout << "Response body: " << res.body() << std::endl;
}

// Base64 encoding functions implementation
std::string base64_encode(const std::string& str) {
    return base64_encode(reinterpret_cast<const unsigned char*>(str.c_str()), str.length());
}

std::string base64_encode(const std::vector<unsigned char>& bytes) {
    return base64_encode(bytes.data(), bytes.size());
}

std::string base64_encode(const unsigned char* bytes, size_t len) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(bytes++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

// Base64 decoding function
std::vector<unsigned char> base64_decode(const std::string& encoded_string) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
        
    std::vector<unsigned char> ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_4[4], char_array_3[3];

    for (char c : encoded_string) {
        if (c == '=') break;
        if (base64_chars.find(c) == std::string::npos) continue;

        char_array_4[i++] = c;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}

// Main function to start the server
int main() {
    try {
        io_context ioc;
        ip::tcp::acceptor acceptor(ioc, ip::tcp::endpoint(ip::tcp::v4(), 8080));
        std::cout << "Server running on http://127.0.0.1:8080" << std::endl;
        
        while (true) {
            ip::tcp::socket socket(ioc);
            acceptor.accept(socket);
            
            flat_buffer buffer;
            http::request<http::string_body> req;
            http::read(socket, buffer, req);

            http::response<http::string_body> res;
            handle_request(req, res);
            http::write(socket, res);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
