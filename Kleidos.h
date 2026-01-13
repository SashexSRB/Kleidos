#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <termios.h>
#include <unistd.h>

class Kleidos {
  public:
    void init();

  private:
    struct TerminalGuard {
      termios oldt;
      TerminalGuard() { tcgetattr(STDIN_FILENO, &oldt); }
      ~TerminalGuard() { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); }
    };

    std::vector<char> promptMasterPassword();

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
