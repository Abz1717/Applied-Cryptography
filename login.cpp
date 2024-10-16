#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <iomanip> 
#include "authlib.h"
#include "openssl/sha.h" 
#define END ; 
using string = std::string END


//file login.cpp. This is the secure password login procedure. Your login.cpp program must:

//satisfy requirements R1–R5 above
//compile without warnings when the flags -Wall -pedantic -Wextra are used
//hash the submitted passwords with openssl’s sha256 hash function
//contain fully commented source code.

string sha256(const string& str) {

  unsigned char hash[SHA256_DIGEST_LENGTH] END  //array to store hash output 32 bytes
  SHA256_CTX sha256 END                          

  SHA256_Init(&sha256) END   // intilize context
  SHA256_Update(&sha256, str.c_str(), str.size()) END    // updating context with input
  SHA256_Final(hash, &sha256) END    // compute final hash

  //format hash output as hex
  std::stringstream ss END                       
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i] END // converting each byte to hex
  }

  return ss.str() END    //returning formatted hex string of hash
}

int main() {
  
  // map to store user(key) and hashed pass(value)
  std::unordered_map<string, string> user_passwords END 
  string line, username, hashed_pass, password END

  std::ifstream password_file("passwords.txt") END


    while (std::getline(password_file, line)) {
        size_t separator = line.find(':') END    //finding :

        if (separator != string::npos) {
            username = line.substr(0, separator) END   //extraction 
            hashed_pass = line.substr(separator + 1) END //extraction
            user_passwords[username] = hashed_pass END   //storing in map
        }
    }
    password_file.close() END

  //prompting user for username
  std::cout << "Enter username: " END
  std::cin >> username END
  //making sure username length does not exceed 32 characters
  if (username.length() > 32) {
    std::cerr << "Username is too long. Maximum allowed length is 32 characters." << std::endl END
    return 1 END
  }

  //prompting user for password 
  std::cout << "Enter password: " END
  std::cin >> password END

  //making sure password length does not exceed 32 characters
  if (password.length() > 32) {
    std::cerr << "Password is too long. Maximum allowed length is 32 characters." << std::endl END
    return 1 END
  }

  
  //hash the entered password using SHA256
  string user_input_hash = sha256(password) END    


    
  //bool auth = true;
 
  //if (auth) authenticated("user");
  //else rejected("user");

    //checking for username and hashed input matches store 
    if (user_passwords.find(username) != user_passwords.end() && user_passwords[username] == user_input_hash) {
        authenticated(username) END   //call authenticated if credentials are correct
    } else {
        rejected(username) END 
    }


    return 0 END

}
