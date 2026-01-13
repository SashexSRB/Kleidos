#include "Kleidos.h"

/**
 * App initialization.
 *
 * Called by user to create a new vault.
 * Gets the master password. Generates the cryptographic params,
 * derives the key, creates the header, 
 * and writes the vault file.
 *
 * @TODO: Implement the necessary functions from private part of the class.
 *
 * @return void
 */
void Kleidos::init() {
  auto mPass = Kleidos::promptMasterPassword();
  std::string passStr(mPass.begin(), mPass.end());
  std::println("{}", passStr);

  auto salt = Kleidos::generateRandomBytes(10);
  std::println("{}", salt);

  auto key = Kleidos::deriveKey(passStr, salt);
  std::println("{}", key);

  std::memset(mPass.data(), 0, mPass.size());
}

/**
 * Prompt & Validate Master Password``
 *
 * Disables echo on terminal, promps input, 
 * stores the password in a vector of chars,
 * due to memory behavior of a string
 * restores terminal to standard
 * @TODO: Implement password matching, if database file exists.
 * Possible solution: On beginning of function, an if statement to check if DB file exists, and use that to match the input password.
 * If DB not present, it will use the input password to make it the master password for the DB file.
 *
 * @return std::vector<char> password;
 */
std::vector<char> Kleidos::promptMasterPassword() {
  std::cout << "Enter Master Password: "; 

  TerminalGuard guard;
  termios newt = guard.oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  std::vector<char> password;
  char c;
  while (std::cin.get(c) && c != '\n') {
    password.push_back(c);
  }

  tcsetattr(STDIN_FILENO, TCSANOW, &guard.oldt);
  std::cout << "\n";

  return password;
}

/**
 * Generate cryptograhically secure random bytes used for salt and nonce
 *
 * Uses openssl to generate a bytes for the header of the DB file.
 *
 * @param size_t length
 * @return std::vector<uint8_t> salt
 */
std::vector<uint8_t> Kleidos::generateRandomBytes(size_t length) {
  std::vector<uint8_t> rndBytes(length);
  if (RAND_bytes(rndBytes.data(), static_cast<int>(length)) != 1) {
    throw std::runtime_error("RAND_bytes failed!");
  }
  return rndBytes;
}

/**
 * Derive a key from the master password and the salt
 *
 * Uses libsodium to generate it.
 *
 * @param const std::string& password
 * @param const std::vector<uint8_t>& salt
 * @param size_t keyLen = 32
 *
 * @return std::vector<uint8_t> key
 */
std::vector<uint8_t> Kleidos::deriveKey(const std::string& password, const std::vector<uint8_t>& salt, size_t keyLen) {
  if (sodium_init() < 0) throw std::runtime_error("libsodium init failed.");
  
  std::vector<uint8_t> key(keyLen);
  if(crypto_pwhash(
        key.data(), keyLen,
        password.c_str(), password.size(),
        salt.data(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
        ) != 0 ) {
    throw std::runtime_error("Key derivation failed (out of memory?)");
  }
  return key;
}
