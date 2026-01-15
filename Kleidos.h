#pragma once

#include "KldIncludes.h"

class Kleidos {
public:
  void init();
  void run();

  struct VaultMeta {
    uint32_t metaVersion;
    uint64_t createdAt;
    uint32_t flags;
  };

private:
  struct TerminalGuard {
    termios oldt;
    TerminalGuard() { tcgetattr(STDIN_FILENO, &oldt); }
    ~TerminalGuard() { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); }
  };

  struct VaultHeader {
    uint16_t version;
    uint8_t kdf_id;
    uint64_t opslimit;
    uint64_t memlimit;
    uint32_t parallelism;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> raw; // exact bytes as read (for AEAD AD)
  };

  static constexpr uint64_t KDF_OPS = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  static constexpr uint64_t KDF_MEM = crypto_pwhash_MEMLIMIT_INTERACTIVE;
  static constexpr uint32_t KDF_PAR = 1;
  const std::string canary = "KLEIDOS_VAULT_OK";

  std::vector<char> promptMasterPassword();
  std::vector<uint8_t> generateRandomBytes(size_t length);
  std::vector<uint8_t> deriveKey(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    size_t keyLen=32
  );
  std::vector<uint8_t> createVaultHeader(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& nonce
  );
  void writeVaultFile(
    const std::string& filename,
    const std::vector<uint8_t>& header,
    const std::vector<uint8_t>& ciphertext
  );

  template<typename T>
  static T read_uint(
    std::ifstream& f,
    std::vector<uint8_t>& raw
  );

  VaultHeader readVaultHeader(std::ifstream& file);
  void unlock(const std::string& filename);

  std::vector<uint8_t> serializeMeta(const VaultMeta& m);
};
