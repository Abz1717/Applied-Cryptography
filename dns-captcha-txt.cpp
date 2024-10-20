#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdlib>
#include <cstring>
#include <iomanip>

#define DNS_SERVER "8.8.8.8" // Assuming a DNS server for CAPTCHA
#define DNS_PORT 53
#define DOMAIN "api.authservice.co.uk" // Hard-coded domain

std::string createDnsRequest(const std::string& domain, bool condition) {
    unsigned char buf[512] = {0};
    int offset = 0;

    // Assign Transaction ID, encoding the condition as part of the ID
    buf[0] = 0x12; // Arbitrary high byte
    buf[1] = condition ? 0x34 : 0x35; // 0x34 for true, 0x35 for false

    // Building DNS Query Header
    buf[2] = 0x01; // Standard query with recursion desired
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

bool handleDnsResponse(const char* buffer, int length) {
    if (length < 12) {
        std::cerr << "Received a response that's too short." << std::endl;
        return false;
    }

    // Check for DNS response errors
    if ((buffer[3] & 0x0F) != 0) {
        std::cerr << "DNS error in response code: " << (buffer[3] & 0x0F) << std::endl;
        return false;
    }

    int pos = 12; // Start past the DNS header

    // Skip the question section
    while (buffer[pos] != 0) {
        pos++;
    }
    pos += 5; // Skip null byte, QTYPE, and QCLASS

    // Begin reading answer section
    while (pos < length) {
        pos += 2; // Skip NAME

        unsigned short type = (buffer[pos] << 8) | buffer[pos + 1];
        pos += 2;

        pos += 2; // Skip CLASS
        pos += 4; // Skip TTL

        unsigned short rdLength = (buffer[pos] << 8) | buffer[pos + 1];
        pos += 2;

        if (type == 0x0010 && pos + rdLength <= length) { // Check for TXT record
            int txtLength = buffer[pos];
            std::string txtRecord(buffer + pos + 1, txtLength);

            std::cout << "Received TXT Record: " << txtRecord << std::endl;

            if (txtRecord == "failed") {
                std::cerr << "Query handling failed according to received response." << std::endl;
                return false;
            }

            // Handle CAPTCHA: Assume the record is formatted as "question|hash"
            size_t delimPos = txtRecord.find('|');
            if (delimPos != std::string::npos) {
                std::string question = txtRecord.substr(0, delimPos);
                std::string receivedHash = txtRecord.substr(delimPos + 1);

                std::cout << "CAPTCHA Question: " << question << std::endl;
                // You could now prompt a user input and verify it against receivedHash
            }

            pos += rdLength; // Move to the next record
        } else {
            pos += rdLength; // Move to the next record
        }
    }

    return true;
}

int main() {
    std::string domain = DOMAIN;
    bool userCondition = true; // The boolean we're encoding into the query

    std::string dnsRequest = createDnsRequest(domain, userCondition);

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DNS_SERVER, &serverAddr.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation failed!" << std::endl;
        return EXIT_FAILURE;
    }

    sendto(sock, dnsRequest.c_str(), dnsRequest.size(), 0, 
           (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    char buffer[512];
    socklen_t addrlen = sizeof(serverAddr);
    int n = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &addrlen);
    if (n < 0) {
        std::cerr << "Failed to receive response!" << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    std::cout << "Received response" << std::endl;

    if (!handleDnsResponse(buffer, n)) {
        std::cerr << "Failed to process the DNS response." << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    shutdown(sock, SHUT_RDWR);
    return 0;
}