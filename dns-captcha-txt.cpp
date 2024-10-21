#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstdlib>
#include "authlib.h"
#include "openssl/sha.h"

#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define DOMAIN_VALID "valid.authservice.co.uk"
#define DOMAIN_INVALID "invalid.authservice.co.uk"

using string = std::string;

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    char outputBuffer[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    outputBuffer[64] = '\0';
    return std::string(outputBuffer);
}

std::string createDnsRequest(const std::string& domain) {
    unsigned char buf[512] = {0}; int offset = 12;
    buf[0] = 0x12; buf[1] = 0x34; buf[2] = 0x01; buf[5] = 0x01;
    for (size_t i = 0, j; i < domain.size();) {
        j = domain.find('.', i);
        if (j == std::string::npos) j = domain.size();
        buf[offset++] = j - i; memcpy(buf + offset, domain.c_str() + i, j - i);
        offset += j - i; i = (j < domain.size()) ? j + 1 : j;
    }
    buf[offset++] = 0; buf[offset++] = 0x00; buf[offset++] = 0x10;
    buf[offset++] = 0x00; buf[offset++] = 0x01;
    return std::string(reinterpret_cast<char*>(buf), offset);
}

bool handleDnsResponse(const char* buffer, int length, std::string& resultHash) {
    if (length < 12 || (buffer[3] & 0x0F) != 0) return false;
    int pos = 12; while (buffer[pos] != 0) pos++;
    pos += 10;
    int txtLength = buffer[pos];
    std::string txtRecord(buffer + pos + 1, txtLength);
    size_t delimPos = txtRecord.find('|');
    if (delimPos != std::string::npos) {
        std::string question = txtRecord.substr(0, delimPos);
        resultHash = txtRecord.substr(delimPos + 1);
        std::cout << "CAPTCHA Question: " << question << "\nCAPTCHA Answer: ";
        return true;
    }
    return false;
}

int main() {/*
    std::unordered_map<string, string> user_passwords;
    std::ifstream password_file("passwords.txt");
    for (string line; std::getline(password_file, line);) {
        size_t separator = line.find(':');
        if (separator != string::npos)
            user_passwords[line.substr(0, separator)] = line.substr(separator + 1);
    }

    string username, password;
    std::cout << "Enter username: "; std::cin >> username;
    std::cout << "Enter password: "; std::cin >> password;

    bool userCondition = user_passwords.count(username) && user_passwords[username] == sha256(password);

    std::string domain = userCondition ? DOMAIN_VALID : DOMAIN_INVALID;
    std::string dnsRequest = createDnsRequest(domain);

    struct sockaddr_in serverAddr {AF_INET, htons(DNS_PORT), {}, {0}};
    inet_pton(AF_INET, DNS_SERVER, &serverAddr.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { std::cerr << "Socket creation failed!\n"; return EXIT_FAILURE; }

    if (sendto(sock, dnsRequest.c_str(), dnsRequest.size(), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Failed to send request!\n"; shutdown(sock, SHUT_RDWR); return EXIT_FAILURE;
    }

    char buffer[512]; socklen_t addrlen = sizeof(serverAddr);
    if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &addrlen) < 0) {
        std::cerr << "Failed to receive response!\n"; shutdown(sock, SHUT_RDWR); return EXIT_FAILURE;
    }

    std::cout << "Received response\n";
    std::string resultHash;
    bool validCaptcha = handleDnsResponse(buffer, addrlen, resultHash);
    
    bool userAuthenticated = false;
    if (validCaptcha) {
        std::string captcha_ans; std::cin >> captcha_ans;
        std::string captcha_ans_hashed = sha256(captcha_ans);
        if (userCondition) {
            userAuthenticated = (captcha_ans_hashed == resultHash);
        } else {
            userAuthenticated = (captcha_ans == "1234"); // Example condition
        }
    }

    if (userAuthenticated) authenticated(username); else rejected(username);

    shutdown(sock, SHUT_RDWR);*/
    return 0;
}