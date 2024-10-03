#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <iomanip> 
#include "authlib.h"
#include "openssl/sha.h" 
using string = std::string;

//file login.cpp. This is the secure password login procedure. Your login.cpp program must:

//satisfy requirements R1–R5 above
//compile without warnings when the flags -Wall -pedantic -Wextra are used
//hash the submitted passwords with openssl’s sha256 hash function
//contain fully commented source code.

string sha256(const string& str) {

  unsigned char hash[SHA256_DIGEST_LENGTH];   //array to store hash output 32 bytes
  SHA256_CTX sha256;                          

  SHA256_Init(&sha256);   // intilize context
  SHA256_Update(&sha256, str.c_str(), str.size());    // updating context with input
  SHA256_Final(hash, &sha256);    // compute final hash

  //format hash output as hex
  std::stringstream ss;                       
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i]; // converting each byte to hex
  }

  return ss.str();    //formatted hex string of hash
}

int main() {
  
  // map to store user(key) and hashed pass(value)
  std::unordered_map<string, string> user_passwords; 
  string line, username, hashed_pass, password;

  std::ifstream password_file("passwords.txt");

    while (std::getline(password_file, line)) {
        size_t separator = line.find(':');    //finding :

        if (separator != string::npos) {
            username = line.substr(0, separator);   //extraction 
            hashed_pass = line.substr(separator + 1); //extraction
            user_passwords[username] = hashed_pass;   //storing user and hashh pass in map
        }
    }
    password_file.close();

  std::cout << "Enter username: ";
  std::cin >> username;

  std::cout << "Enter password: ";
  std::cin >> password;

  
  string user_input_hash = sha256(password);    //hash user pass using sha 256 function


    
  //bool auth = true;
 
  //if (auth) authenticated("user");
  //else rejected("user");

    //checking for username and hashed input matches store 
    if (user_passwords.find(username) != user_passwords.end() && user_passwords[username] == user_input_hash) {
        authenticated(username); 
    } else {
        rejected(username); 
    }


    return 0;

}
