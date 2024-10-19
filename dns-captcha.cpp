#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdlib>
#include <openssl/sha.h> // Für SHA-256

#define DNS_SERVER "8.8.8.8" // Assuming a DNS server for CAPTCHA
#define DNS_PORT 53

std::string createDnsRequest(const std::string& domain) {
    unsigned char buf[512] = {0};
    int offset = 12;

    // DNS-Anfrage aufbauen
    std::string currentDomain = domain + ".";
    for (size_t i = 0; i < currentDomain.size(); ++i) {
        size_t dotPos = currentDomain.find('.', i);
        if (dotPos == std::string::npos) dotPos = currentDomain.size();
        buf[offset++] = dotPos - i; // Länge des Tokens
        memcpy(buf + offset, currentDomain.c_str() + i, dotPos - i);
        offset += dotPos - i;
        i = dotPos;
    }

    buf[offset++] = 0; // Null-Terminierung
    buf[offset++] = 0x00; buf[offset++] = 0x01; // Typ: A
    buf[offset++] = 0x00; buf[offset++] = 0x01; // Klasse: IN

    return std::string(reinterpret_cast<char*>(buf), offset);
}

std::string hashString(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    
    char outputBuffer[65]; // 64 characters for SHA-256 + null terminator
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = '\0'; // Null terminieren
    return std::string(outputBuffer);
}

bool verifyCaptcha(const std::string& receivedHash, const std::string& userInput) {
    std::string hashedInput = hashString(userInput);
    return (hashedInput == receivedHash);
}

int main() {
    std::string domain;
    std::cout << "Enter the domain you want to query: ";
    std::cin >> domain;

    std::string dnsRequest = createDnsRequest(domain);
    
    // DNS-Server-Adresse auflösen
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DNS_SERVER, &serverAddr.sin_addr);

    // Socket erstellen
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation failed!" << std::endl;
        return EXIT_FAILURE;
    }

    // DNS-Anfrage senden
    sendto(sock, dnsRequest.c_str(), dnsRequest.size(), 0, 
           (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    // Antwort empfangen
    char buffer[512];
    socklen_t addrlen = sizeof(serverAddr);
    int n = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &addrlen);
    if (n < 0) {
        std::cerr << "Failed to receive response!" << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    buffer[n] = '\0'; // Null terminieren
    // Hier gehen wir davon aus, dass wir im Buffer den SHA-256 Hash empfangen
    std::string receivedHash(buffer); // Dies sollte der echte Hash sein
    std::string userInput;

    std::cout << "Please solve the CAPTCHA: "; // Hier könnte eine spezifische CAPTCHA-Anweisung stehen
    std::cin >> userInput;

    // CAPTCHA prüfen
    if (verifyCaptcha(receivedHash, userInput)) {
        std::cout << "CAPTCHA verified successfully!" << std::endl;
    } else {
        std::cerr << "CAPTCHA verification failed! Exiting." << std::endl;
        shutdown(sock, SHUT_RDWR);
        return EXIT_FAILURE;
    }

    shutdown(sock, SHUT_RDWR); // Socket schließen
    return 0;
}