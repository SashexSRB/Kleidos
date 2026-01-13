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
  auto salt = Kleidos::generateRandomBytes(10);
  auto key = Kleidos::deriveKey(std::string(mPass.begin(), mPass.end()), salt);
  auto nonce = Kleidos::generateRandomBytes(12);

  auto header = Kleidos::createVaultHeader(salt, nonce);

  std::println("{}", key);
  std::println("{}", header);

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

/**
 * Generates a vault header for the vault file in order to derive the key from it. The workflow in mind:
 * 1. Password input
 * 2. Header (plaintext) -> contains everything needed to re-derive the key (KDF algo identifier, KDF params, salt)
 * 3. deriveKey(password, salt, keyLength) -> produces the key
 * 4. Key -> used only for encryption/decryption of vault data, never written to disk
 *
 * @param const std::vector<uint8_t>& salt
 * @param const std::vector<uint8_t>& nonce
 *
 * @return std::vector<uint8_t> header
 */
std::vector<uint8_t> Kleidos::createVaultHeader(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& nonce) {
  std::vector<uint8_t> header;
  header.reserve(64);

  // Magic
  const uint8_t magic[4] = {'K', 'L', 'E', 'I'};
  header.insert(header.end(), magic, magic+4);

  // Version
  uint16_t version = 1;
  header.push_back(static_cast<uint8_t>(version >> 8));
  header.push_back(static_cast<uint8_t>(version));

  // Argon2id parameters (example values)
  uint32_t m_cost = 1 << 16;
  uint32_t t_cost = 3;
  uint32_t parallelism = 1;

  auto push_u32 = [&header](uint32_t v) {
    header.push_back(v >> 24);
    header.push_back(v >> 16);
    header.push_back(v >> 8);
    header.push_back(v);
  };

  push_u32(m_cost);
  push_u32(t_cost);
  push_u32(parallelism);

  // Salt
  header.push_back(static_cast<uint8_t>(salt.size()));
  header.insert(header.end(), salt.begin(), salt.end());

  // Nonce
  header.push_back(static_cast<uint8_t>(nonce.size()));
  header.insert(header.end(), nonce.begin(), nonce.end());

  return header;
}

