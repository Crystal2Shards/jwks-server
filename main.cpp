# Include necessary libraries
#include <iostream>
#include <string>
#include <map>
#include <nlohmann/json.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <jwt-cpp/jwt.h>
#include <httplib.h>

using json = nlohmann::json;

// Function to generate RSA key pair
std::pair<std::string, std::string> generate_rsa_key() {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        throw std::runtime_error("Failed to generate RSA key");
    }
    BIO *bio_private = BIO_new(BIO_s_mem());
    BIO *bio_public = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(bio_public, rsa);
    
    char *private_key = nullptr;
    char *public_key = nullptr;
    long private_len = BIO_ctrl_pending(bio_private);
    long public_len = BIO_ctrl_pending(bio_public);
    private_key = (char *)malloc(private_len + 1);
    public_key = (char *)malloc(public_len + 1);
    BIO_read(bio_private, private_key, private_len);
    BIO_read(bio_public, public_key, public_len);
    private_key[private_len] = '\0';
    public_key[public_len] = '\0';
    
    BIO_free_all(bio_private);
    BIO_free_all(bio_public);
    RSA_free(rsa);
    
    return {std::string(private_key), std::string(public_key)};
}

// Function to create JWT
std::string create_jwt(const std::string &private_key) {
    auto token = jwt::create()
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(1))
        .set_payload_claim("sub", jwt::claim(std::string("user_id")))
        .sign(jwt::rs256(private_key, ""));
    return token;
}

int main() {
    // Generate RSA key pair
    auto [private_key, public_key] = generate_rsa_key();
    
    // Create HTTP server
    httplib::Server svr;
    
    // Endpoint to serve JWKS
    svr.Get("/jwks", [&public_key](const httplib::Request &, httplib::Response &res) {
        json jwks = { {"keys", json::array({ {
            {"kty", "RSA"},
            {"n", public_key},
            {"e", "AQAB"},
            {"use", "sig"}
        }}) }} };  
        res.set_content(jwks.dump(), "application/json");
    });
    
    // Endpoint to authenticate users
    svr.Post("/auth", [&private_key](const httplib::Request &req, httplib::Response &res) {
        // Here you should validate user credentials (omitted for simplicity)
        // If valid, create and return JWT
        std::string token = create_jwt(private_key);
        res.set_content(token, "text/plain");
    });
    
    // Start the server on port 8080
    svr.listen("0.0.0.0", 8080);
    return 0;
}
