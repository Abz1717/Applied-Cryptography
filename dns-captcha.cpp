#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdlib>
#include <cstring>
#include <openssl/sha.h>

#define DNS_SERVER "8.8.8.8" // Assuming a DNS server for CAPTCHA
#define DNS_PORT 53
#define DOMAIN "api.authservice.co.uk" // Hard-coded domain

std::string createDnsRequest(const std::string& domain) {
    unsigned char buf[512] = {0};
    int offset = 12;

    // Building DNS Query
    std::string currentDomain = domain + ".";
    for (size_t i = 0; i < currentDomain.size(); ++i) {
        size_t dotPos = currentDomain.find('.', i);
        if (dotPos == std::string::npos) dotPos = currentDomain.size();
        buf[offset++] = dotPos - i; // Length of the token
        memcpy(buf + offset, currentDomain.c_str() + i, dotPos - i);
        offset += dotPos - i;
        i = dotPos;
    }

    buf[offset++] = 0; // Null terminator
    buf[offset++] = 0x00; buf[offset++] = 0x01; // Type: A
    buf[offset++] = 0x00; buf[offset++] = 0x01; // Class: IN

    return std::string(reinterpret_cast<char*>(buf), offset);
}

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    
    char outputBuffer[65]; // 64 characters for SHA-256 + null terminator
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = '\0'; // Null terminator
    return std::string(outputBuffer);
}

bool verifyCaptcha(const std::string& receivedHash, const std::string& userInput) {
    std::string hashedInput = sha256(userInput);
    return (hashedInput == receivedHash);
}

std::string getReadableResponse(const char* buffer, int length) {
    // Assuming the response contains valid UTF-8 characters
    std::string response(buffer, length); // Construct string from buffer

    // Try to decode the response as needed
    return response; // For now just return the raw string
}

int main() {
    // Use the hard-coded domain
    std::string domain = DOMAIN;

    std::string dnsRequest = createDnsRequest(domain);
    
    // Resolve DNS server address
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DNS_SERVER, &serverAddr.sin_addr);

    // Build socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // Sending DNS request
    sendto(sock, dnsRequest.c_str(), dnsRequest.size(), 0, 
           (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    // Receiving response
    char buffer[512];
    socklen_t addrlen = sizeof(serverAddr);
    int n = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &addrlen);
    if (n < 0) {
        std::cerr << "Failed to receive response!" << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    buffer[n] = '\0'; // Null terminator
    
    // Get a readable response
    std::string readableResponse = getReadableResponse(buffer, n);
    
    // For debugging, print the response content
    std::cout << "DNS Response (readable): " << readableResponse << std::endl;

    // Assuming a simple format where the response is "CAPTCHA Question|HASH"
    std::string delimiter = "|";
    size_t delimPos = readableResponse.find(delimiter);

    if (delimPos == std::string::npos) {
        std::cerr << "Invalid response format!" << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }
    
    std::string captchaQuestion = readableResponse.substr(0, delimPos);
    std::string receivedHash = readableResponse.substr(delimPos + 1);

    // Output the CAPTCHA question
    std::cout << "Please solve the CAPTCHA: " << captchaQuestion << std::endl; 
    std::string userInput;
    std::cin >> userInput;

    // CAPTCHA verification
    if (verifyCaptcha(receivedHash, userInput)) {
        std::cout << "CAPTCHA verified successfully!" << std::endl;
    } else {
        std::cerr << "CAPTCHA verification failed! Exiting." << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    shutdown(sock, SHUT_RDWR); // Close the socket
    return 0;
}