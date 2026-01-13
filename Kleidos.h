#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <termios.h>
#include <unistd.h>

class Kleidos {
  public:
    // Called by user to create a new vault.
    void init();
    // Hint: orchestrates the whole vault creation process
    // Steps: get master password, generate cryptographic params, derive key, create header, write file

  private:
    struct TerminalGuard {
      termios oldt;
      TerminalGuard() { tcgetattr(STDIN_FILENO, &oldt); }
      ~TerminalGuard() { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); }
    };

    // Prompt & Validate Master Secret
    std::vector<char> promptMasterPassword();
    // Hint: securely read password from stdin without echo, confirm password matches

    // Cryptographic setup
    std::vector<uint8_t> generateSalt(size_t length=10);
    // Hint: generate cryptographically secure random bytes for KDF salt

    std::vector<uint8_t> deriveKey(const std::string& password, const std::vector<uint8_t>& salt);
    // Hint: use memory-hard KDF (e.g., Argon2id) with proper parameters

    std::vector<uint8_t> generateNonce(size_t length=12);
    // Hint: unique nonce for encryption, may be per vault or per entry

    // Header & Metadata
    void createVaultHeader(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& nonce);
    // Hint: store vault format version, salt, KDF params, nonces
    // Header may be partially plaintext but must allow safe unlocking later
    
    // File operations
    void writeVaultFile(const std::string& filename, const std::vector<uint8_t>& header);
    // Hint: Create new file, write header, ensure no plaintext secrets ever written
};
