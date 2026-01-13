#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <termios.h>
#include <unistd.h>

class Kleidos {
  public:
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
    void init();

  private:
    struct TerminalGuard {
      termios oldt;
      TerminalGuard() { tcgetattr(STDIN_FILENO, &oldt); }
      ~TerminalGuard() { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); }
    };

    /**
     * Prompt & Validate Master Password``
     *
     * Disables echo on terminal, promps input, 
     * stores the password in a vector of chars,
     * due to memory behavior of a string
     * restores terminal to standard
     * @TODO: Implement password matching, if database file exists.
     *
     * @return std::vector<char> password;
     */
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
