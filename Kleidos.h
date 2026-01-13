#pragma once

#include "KldIncludes.h"

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
    std::vector<uint8_t> generateRandomBytes(size_t length);
    std::vector<uint8_t> deriveKey(const std::string& password, const std::vector<uint8_t>& salt, size_t keyLen=32);

    std::vector<uint8_t> createVaultHeader(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& nonce);
    // File operations
    void writeVaultFile(const std::string& filename, const std::vector<uint8_t>& header);
    // Hint: Create new file, write header, ensure no plaintext secrets ever written
};
