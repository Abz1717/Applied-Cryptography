#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdlib>
#include <cstring>
#include <openssl/sha.h>
#include <iomanip>

#define DNS_SERVER "8.8.8.8" // DNS server for CAPTCHA
#define DNS_PORT 53
#define DOMAIN "api.authservice.co.uk" // Hard-coded domain

std::string createDnsRequest(const std::string& domain) {
    unsigned char buf[512] = {0};
    int offset = 0;

    // Building DNS Query Header
    buf[0] = 0; buf[1] = 0; // Transaction ID
    buf[2] = 0x01; // Standard query
    buf[5] = 0x01; // One question

    offset = 12; // Header is 12 bytes
    
    std::string currentDomain = domain + ".";
    for (size_t i = 0; i < currentDomain.size(); ++i) {
        size_t dotPos = currentDomain.find('.', i);
        if (dotPos == std::string::npos) dotPos = currentDomain.size();
        buf[offset++] = dotPos - i; // Length of each label
        memcpy(buf + offset, currentDomain.c_str() + i, dotPos - i);
        offset += dotPos - i;
        i = dotPos;
    }

    buf[offset++] = 0; // Null terminator for domain name
    buf[offset++] = 0x00; buf[offset++] = 0x10; // Type: TXT (0x0010)
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

void printHex(const char* data, int length) {
    std::cout << "DNS Response (hex): ";
    for (int i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(data[i]) & 0xFF) << " ";
    }
    std::cout << std::dec << std::endl; // Switch back to decimal
}

int main() {
    // Use the hard-coded domain
    std::string domain = DOMAIN;

    std::string dnsRequest = createDnsRequest(domain);
    
    // Resolving DNS server address
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

    printHex(buffer, n); // Print the response in hex format for debugging

    // Check DNS response header
    if (buffer[3] & 0x03) { // Check the Response Code field (last 3 bits of byte 3)
        std::cerr << "DNS query failed with response code: " << (buffer[3] & 0x0F) << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    // Move past the DNS header and question sections to reach the answer section
    int pos = 12; // Start past the DNS header
    while (buffer[pos] != 0) { // Skip QNAME
        pos++;
    }
    pos += 5; // Skip null byte, QTYPE, and QCLASS

    // Parse the DNS answers
    bool foundCaptcha = false;
    while (pos < n) {
        // Skip the NAME part, which is a pointer, hence 2 bytes
        pos += 2;

        // Check the TYPE
        unsigned short type = (buffer[pos] << 8) | buffer[pos + 1];
        pos += 2;

        // Skip CLASS
        pos += 2;

        // Skip TTL
        pos += 4;

        // Get RD_LENGTH
        unsigned short length = (buffer[pos] << 8) | buffer[pos + 1];
        pos += 2;

        if (type == 0x0010) { // TXT record
            // Read TXT data
            int txtLength = buffer[pos];
            std::string txtRecord(buffer + pos + 1, txtLength);
            
            std::cout << "Received TXT Record: " << txtRecord << std::endl;
            
            std::string delimiter = "|";
            size_t delimPos = txtRecord.find(delimiter);

            if (delimPos != std::string::npos) {
                foundCaptcha = true;
                std::string captchaQuestion = txtRecord.substr(0, delimPos);
                std::string receivedHash = txtRecord.substr(delimPos + 1);

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
            }
            pos += length; // Move to the next record
        } else {
            pos += length; // Skip non-TXT records
        }
    }

    if (!foundCaptcha) {
        std::cerr << "CAPTCHA TXT record not found!" << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    shutdown(sock, SHUT_RDWR); // Close the socket
    return 0;
}