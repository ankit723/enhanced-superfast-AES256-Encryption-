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
    try {
        json request_json = json::parse(req.body());
        std::vector<unsigned char> key(AES_KEY_SIZE, 0x00); // Sample fixed key
        RAND_bytes(key.data(), AES_KEY_SIZE);

        if (req.target() == "/encrypt") {
            std::vector<unsigned char> iv = generateIV();
            std::vector<unsigned char> tag(TAG_SIZE);
            std::string ciphertext = encryptAES(request_json["plaintext"], key, iv, tag);

            json response_json = { {"ciphertext", ciphertext}, {"iv", iv}, {"tag", tag} };
            res.result(http::status::ok);
            res.body() = response_json.dump();
        } else if (req.target() == "/decrypt") {
            std::string plaintext = decryptAES(request_json["ciphertext"], key, request_json["iv"], request_json["tag"]);
            json response_json = { {"plaintext", plaintext} };
            res.result(http::status::ok);
            res.body() = response_json.dump();
        } else {
            res.result(http::status::not_found);
            res.body() = "Invalid endpoint";
        }
    } catch (const std::exception& e) {
        res.result(http::status::bad_request);
        res.body() = e.what();
    }
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
            http::request<http::string_body> req;
            http::read(socket, boost::beast::flat_buffer(), req);

            http::response<http::string_body> res;
            handle_request(req, res);
            http::write(socket, res);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
