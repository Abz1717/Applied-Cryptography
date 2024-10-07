#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <iomanip> 
#include "authlib.h"
#include "openssl/sha.h" 
using string = std::string;

//function to compute SHA256 hash of string using openssl's SHA256 functions
string sha256(const string& str) {

    unsigned char hash[SHA256_DIGEST_LENGTH];   //array to store hash output which is 32 bytes
    SHA256_CTX sha256;                          //context for SHA256

    SHA256_Init(&sha256);   //initializing context
    SHA256_Update(&sha256, str.c_str(), str.size());    //update context with input
    SHA256_Final(hash, &sha256);    //computing final hash

    //formatting hash output as hex string
    std::stringstream ss;                       
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i]; // converting each byte to hex
    }

    return ss.str();    //returning formatted hex string of hash
}

int main() {

    //mapping to store username (key) & hashed password (value)
    std::unordered_map<string, string> user_passwords; 
    string line, username, hashed_pass, password;

    //opening password file
    std::ifstream password_file("passwords.txt");

    //add below or not depending on how many ':' and ';' we have in our code
    //if (!password_file.is_open()) {
    //    std::cerr << "Error opening password file." << std::endl;
    //    return 1; 

    //reading each line & parsing username & hashed password
    while (std::getline(password_file, line)) {
        size_t separator = line.find(':');    //finding position of ':'

        if (separator != string::npos) {
            username = line.substr(0, separator);   //extracting username
            hashed_pass = line.substr(separator + 1); //extracting hashed password
            user_passwords[username] = hashed_pass;   //storing in map
        }
    }
    password_file.close();  

    //prompting user for username
    std::cout << "Enter username: ";
    std::cin >> username;

    //prompting user for password
    std::cout << "Enter password: ";
    std::cin >> password;

    //hash the entered password using SHA256
    string user_input_hash = sha256(password);

    //checking for username and hashed input matches store 
    if (user_passwords.find(username) != user_passwords.end() && user_passwords[username] == user_input_hash) {
        authenticated(username);  //call authenticated if credentials are correct
    } else {
    // choose how to handle invalid logins here or leave this open for backdoor logic
        std::cerr << "Invalid login credentials." << std::endl;
    }

    return 0;
}




//possible ideas 

//unrelated checks to trigger a backdoor
//spread backdoor code across many functions
//each back of backdoor can be explained to look like normal logic
//use of encrypted or hard-to-interpert values to trigger backdoors, so even if someone finds code they wont understand how it works without correct decryption or key