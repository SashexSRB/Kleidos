#include "Kleidos.h"

/**
 * App initialization.
 *
 * Called by the run() function in case there is no vault file.
 * Gets the master password. Generates the cryptographic params,
 * derives the key, creates the header, 
 * and writes the vault file.
 */
void Kleidos::init() {
  auto pass = Kleidos::promptMasterPassword();
  auto salt = Kleidos::generateRandomBytes(16);
  auto nonce = Kleidos::generateRandomBytes(12);

  auto key = Kleidos::deriveKey(std::string(pass.begin(), pass.end()), salt);
  auto header = Kleidos::createVaultHeader(salt, nonce);
 
  VaultMeta meta;
  meta.metaVersion = 1;
  meta.createdAt = static_cast<uint64_t>(std::time(nullptr));
  meta.flags = 0;

  std::vector<VaultEntry> entries;
  auto metaBytes = Kleidos::serializeMeta(meta);
  auto entryBytes = Kleidos::serializeEntries(entries);

  std::vector<uint8_t> payload;
  payload.reserve(metaBytes.size() + entryBytes.size());
  payload.insert(payload.end(), metaBytes.begin(), metaBytes.end());
  payload.insert(payload.end(), entryBytes.begin(), entryBytes.end());

  std::vector<uint8_t> ciphertext(payload.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long clen;

  crypto_aead_chacha20poly1305_ietf_encrypt(
    ciphertext.data(), &clen,
    payload.data(), payload.size(),
    header.data(), header.size(),
    nullptr,
    nonce.data(),
    key.data()
  );

  writeVaultFile(getVaultPath(), header, ciphertext);

  std::memset(pass.data(), 0, pass.size());
  sodium_memzero(key.data(), key.size());

  std::cout << "Vault initialized successfully\n";
}

/**
 * Prompt & Validate Master Password
 *
 * Disables echo on terminal, promps input,
 * stores the password in a vector of chars,
 * due to memory behavior of a string
 * restores terminal to standard
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
 */
std::vector<uint8_t> Kleidos::deriveKey(
  const std::string& password, 
  const std::vector<uint8_t>& salt, 
  size_t keyLen
  ) {
  if (sodium_init() < 0) throw std::runtime_error("libsodium init failed.");
  
  std::vector<uint8_t> key(keyLen);
  if(crypto_pwhash(
        key.data(), keyLen,
        password.c_str(), password.size(),
        salt.data(),
        KDF_OPS,
        KDF_MEM,
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
 */
std::vector<uint8_t> Kleidos::createVaultHeader(
  const std::vector<uint8_t>& salt, 
  const std::vector<uint8_t>& nonce
  ) {
  std::vector<uint8_t> header;
  header.reserve(64);

  // Magic
  const uint8_t magic[4] = {'K', 'L', 'E', 'I'};
  header.insert(header.end(), magic, magic+4);

  // Version
  uint16_t version = 1;
  header.push_back(static_cast<uint8_t>(version >> 8));
  header.push_back(static_cast<uint8_t>(version));

  // KDF algorhithm idenfitier (1 = Argon2id via libsodium)
  header.push_back(1);
  
  // libsodium Argon2id params
  uint64_t opslimit = KDF_OPS;
  uint64_t memlimit = KDF_MEM;
  uint32_t parallelism = 1;

  auto push_u32 = [&header](uint32_t v) {
    header.push_back(v >> 24);
    header.push_back(v >> 16);
    header.push_back(v >> 8);
    header.push_back(v);
  };

  auto push_u64 = [&header](uint64_t v) {
    for (int i = 7; i >= 0; --i) {
      header.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
  };

  push_u64(opslimit);
  push_u64(memlimit);
  push_u32(parallelism);

  // Salt
  header.push_back(static_cast<uint8_t>(salt.size()));
  header.insert(header.end(), salt.begin(), salt.end());

  // Nonce
  header.push_back(static_cast<uint8_t>(nonce.size()));
  header.insert(header.end(), nonce.begin(), nonce.end());

  return header;
}

/**
 * Creates a new file, writes header, and the ciphertext
 *
 * @param const std::string& filename
 * @param const std::vector<uint8_t>& header
 * @param const std::vector<uint8_t>& ciphertext
 */
void Kleidos::writeVaultFile(
  const std::string& filename,
  const std::vector<uint8_t>& header,
  const std::vector<uint8_t>& ciphertext
  ) {
  std::ifstream existing(filename, std::ios::binary);
  if (existing.good()) {
    throw std::runtime_error("Vault file already exists");
  }

  std::ofstream file(
    filename,
    std::ios::binary | std::ios::out | std::ios::trunc
  );

  if (!file) {
    throw std::runtime_error("Failed to create vault file");
  }

  file.write(reinterpret_cast<const char*>(header.data()), header.size());
  if (!file) {
    throw std::runtime_error("Failed to write vault header");
  }

  if (!ciphertext.empty()) {
    file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    if (!file) {
      throw std::runtime_error("Failed to write vault payload");
    }
  }

  file.flush();
  if (!file) {
    throw std::runtime_error("Failed to flush vault file");
  }
}

/**
 * Overwrites the existing header file.
 *
 * @param const std::string& filename
 * @param const std::vector<uint8_t>& header
 * @param const std::vector<uint8_t>& ciphertext
 */
void Kleidos::overwriteVaultFile(const std::string& filename, const std::vector<uint8_t>& header, const std::vector<uint8_t>& ciphertext) {
  std::ofstream file(filename, std::ios::binary | std::ios::out | std::ios::trunc);

  if (!file) {
    throw std::runtime_error("Failed to open vault file for overwrite");
  }

  file.write(reinterpret_cast<const char*>(header.data()), header.size());
  if (!file) {
    throw std::runtime_error("Failed to write vault header");
  }

  if (!ciphertext.empty()) {
    file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    if (!file) {
      throw std::runtime_error("Failed to write vault payload");
    }
  }

  file.flush();
  if (!file) {
    throw::std::runtime_error("Failed to write vault file");
  }
}

/**
 * Helper function template to read unsigned int values from header. Replaced the read_u16, read_u32 and read_u64.
 *
 * @param std::ifstream& f
 * @param std::vector<uint8_t>& raw
 */
template<typename T>
T Kleidos::read_uint(
  std::ifstream& f, 
  std::vector<uint8_t>& raw
  ) {
  uint8_t buffer[sizeof(T)];
  f.read(reinterpret_cast<char*>(buffer), sizeof(T));
  raw.insert(raw.end(), buffer, buffer + sizeof(T));

  T value = 0;
  for (size_t i = 0; i < sizeof(T); ++i) {
    value = (value << 8) | buffer[i];
  }
  return value;
}

/**
 * Function to read the vault file's header for the data necessary.
 *
 * @param std::ifstream& file
 */
Kleidos::VaultHeader Kleidos::readVaultHeader(std::ifstream& file) {
  VaultHeader h;
  h.raw.clear();

  auto ensure = [&file]() {
    if (!file) throw std::runtime_error("Unexpected end of vault file");
  };

  // Magic
  uint8_t magic[4];
  file.read(reinterpret_cast<char*>(magic),4);
  ensure();
  h.raw.insert(h.raw.end(),magic,magic+4);
  if (std::memcmp(magic,"KLEI",4) != 0)
    throw std::runtime_error("Invalid vault magic");
  
  // Version
  h.version = read_uint<uint16_t>(file, h.raw);
  if (h.version != 1)
    throw std::runtime_error("Unsupported vault version");

  // KDF id
  uint8_t kdf;
  file.read(reinterpret_cast<char*>(&kdf),1);
  ensure();
  h.raw.push_back(kdf);
  h.kdf_id = kdf;
  if (h.kdf_id != 1)
    throw std::runtime_error("Unsupported KDF");

  // KDF params
  h.opslimit = read_uint<uint64_t>(file, h.raw);
  if (h.opslimit < crypto_pwhash_OPSLIMIT_MIN) 
    throw std::runtime_error("opslimit too low");

  h.memlimit = read_uint<uint64_t>(file, h.raw);
  if (h.memlimit < crypto_pwhash_MEMLIMIT_MIN || h.memlimit > (1ULL << 30))
    throw std::runtime_error("memlimit out of range");

  h.parallelism = read_uint<uint32_t>(file, h.raw);
  if(h.parallelism == 0 || h.parallelism > 16)
    throw std::runtime_error("Invalid Argon2 parallelism");
  
  // Salt
  uint8_t saltLen;

  file.read(reinterpret_cast<char*>(&saltLen), 1);
  ensure();
  h.raw.push_back(saltLen);
  h.salt.resize(saltLen);

  if (saltLen != crypto_pwhash_SALTBYTES)
    throw std::runtime_error("Invalid salt length");

  file.read(reinterpret_cast<char*>(h.salt.data()), saltLen);
  ensure();
  h.raw.insert(h.raw.end(), h.salt.begin(), h.salt.end());

  // Nonce
  uint8_t nonceLen;

  file.read(reinterpret_cast<char*>(&nonceLen),1);
  ensure();
  h.raw.push_back(nonceLen);
  h.nonce.resize(nonceLen);

  if (nonceLen != crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
    throw std::runtime_error("Invalid nonce length");

  file.read(reinterpret_cast<char*>(h.nonce.data()), nonceLen);
  ensure();
  h.raw.insert(h.raw.end(), h.nonce.begin(), h.nonce.end());

  if (h.raw.size() > 256)
    throw std::runtime_error("Header too large");

  return h;
}

/**
 * Function to unlock a vault and retrieve all useful data
 * 
 * @param const std::string& filename
 * @param const std::vector<char>& pass
 *
 */
Kleidos::UnlockResult Kleidos::unlockCore(const std::string& filename, const std::vector<char>& pass) {
  std::ifstream file(filename, std::ios::binary);
  if (!file) throw std::runtime_error("Failed to open vault file");

  // 1. Read header
  VaultHeader header = readVaultHeader(file);

  // 2. Read ciphertext
  std::vector<uint8_t> ciphertext(
    std::istreambuf_iterator<char>(file),
    {}
  );

  if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES)
    throw std::runtime_error("Vault ciphertext truncated");

  // 3. Re-derive key using header params
  std::vector<uint8_t> key(32);
  if (crypto_pwhash(
    key.data(), key.size(),
    pass.data(), pass.size(),
    header.salt.data(),
    header.opslimit,
    header.memlimit,
    crypto_pwhash_ALG_ARGON2ID13
  ) != 0) {
    throw std::runtime_error("Key derivation failed");
  };

  // 5. Decrypt payload
  std::vector<uint8_t> plaintext(ciphertext.size());
  unsigned long long plen;

  if (crypto_aead_chacha20poly1305_ietf_decrypt(
    plaintext.data(), &plen,
    nullptr,
    ciphertext.data(), ciphertext.size(),
    header.raw.data(), header.raw.size(),
    header.nonce.data(),
    key.data()
  ) != 0) {
    std::cout << "Invalid password or corrupted vault\n";
    sodium_memzero(key.data(), key.size());
    sodium_memzero(key.data(), key.size());
    std::exit(EXIT_FAILURE);
  };

  plaintext.resize(plen);

  // 6. verify metadata
  VaultMeta meta;
  size_t offset = 0;

  // metaVersion
  meta.metaVersion = (plaintext[offset] << 24) | (plaintext[offset+1] << 16) |
                    (plaintext[offset+2] << 8) | plaintext[offset+3];
  offset += 4;

  if (meta.metaVersion != 1)
    throw std::runtime_error("Unsupported metadata version");

  // createdAt
  meta.createdAt = 0;
  for (int i = 0; i < 8; ++i) {
      meta.createdAt = (meta.createdAt << 8) | plaintext[offset + i];
  }
  offset += 8;

  // flags
  meta.flags = (plaintext[offset] << 24) | (plaintext[offset+1] << 16) |
              (plaintext[offset+2] << 8) | plaintext[offset+3];
  offset += 4;

  // 7. Deserialize Entries
  std::vector<uint8_t> entryData(plaintext.begin() + offset, plaintext.end());
  auto entries = Kleidos::deserializeEntries(entryData);

  return {header, meta, key, entries};
}


/**
 * Function to unlock the vault for further usage
 * Called by the run() function in main
 *
 * @param const std::string& filename
 */
void Kleidos::unlock(const std::string& filename) {
  auto pass = promptMasterPassword();
  UnlockResult res = unlockCore(filename, pass);

  std::cout << "Vault unlocked successfully\n";

  // Cleanup
  sodium_memzero(res.key.data(), res.key.size());
  sodium_memzero(pass.data(), pass.size());
}

/**
 * Function to serialize vault meta informations
 *
 * @param const Kleidos::VaultMeta& m
 */
std::vector<uint8_t> Kleidos::serializeMeta(const Kleidos::VaultMeta& m) {
  std::vector<uint8_t> out;

  auto push_u32 = [&out](uint32_t v) {
    out.push_back(v >> 24);
    out.push_back(v >> 16);
    out.push_back(v >> 8);
    out.push_back(v);
  };

  auto push_u64 = [&out](uint64_t v) {
    for (int i = 7; i >= 0; --i)
      out.push_back(v >> (i * 8));
  };

  push_u32(m.metaVersion);
  push_u64(m.createdAt);
  push_u32(m.flags);

  return out;
}

/**
 * Function to serialize vault entries for storage in the vault.
 *
 * @param const std::vector<VaultEntry>& entries
 */
std::vector<uint8_t> Kleidos::serializeEntries(const std::vector<VaultEntry>& entries) {
  std::vector<uint8_t> out;

  for (const auto& e : entries) {
    uint16_t keyLen = e.key.size();
    uint16_t valLen = e.value.size();

    // Write key length
    out.push_back(keyLen >> 8);
    out.push_back(keyLen & 0xFF);
    // Write key bytes
    out.insert(out.end(), e.key.begin(), e.key.end());

    // Write value length
    out.push_back(valLen >> 8);
    out.push_back(valLen & 0xFF);
    // Write value bytes
    out.insert(out.end(), e.value.begin(), e.value.end());
  }

  return out;
}

/**
 * Function to deserialize vault entries from decrypted payload
 *
 * @param const std::vector<uint8_t>& data
 */
std::vector<Kleidos::VaultEntry> Kleidos::deserializeEntries(const std::vector<uint8_t>& data) {
  std::vector<VaultEntry> entries;
  size_t offset = 0;

  while (offset + 4 <= data.size()) {
    uint16_t keyLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (offset + keyLen + 2 > data.size()) break;

    std::string key(data.begin() + offset, data.begin() + offset + keyLen);
    offset += keyLen;

    uint16_t valLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (offset + valLen > data.size()) break;

    std::string value(data.begin() + offset, data.begin() + offset + valLen);
    offset += valLen;

    entries.push_back({key, value});
  }

  return entries;
};

/**
 * Add a new entry to the vault in memory
 *
 * @param std::vector<VaultEntry>& entries
 * @param const std::string& key,
 * @param const std::string& value
 */
void Kleidos::addEntry(std::vector<VaultEntry>& entries, const std::string& key, const std::string& value) {
  entries.push_back({key, value});
}

/**
 * Update an existing entry by key
 *
 * @param std::vector<VaultEntry>& entries,
 * @param const std::string& key,
 * @param const std::string& newValue
 */
bool Kleidos::updateEntry(std::vector<VaultEntry>& entries, const std::string& key, const std::string& newValue) {
  for (auto& e : entries) {
    if (e.key == key) {
      e.value = newValue;
      return true;
    }
  }
  return false;
}

/**
 * Remove an entry by key
 * 
 * @param std::vector<VaultEntry>& entries
 * @param const std::string& key
 */
bool Kleidos::removeEntry(std::vector<VaultEntry>& entries, const std::string& key) {
  auto it = std::remove_if(
    entries.begin(), 
    entries.end(),
    [&](const VaultEntry& e) {
      return e.key == key;
    }
  );

  if (it != entries.end()) {
    entries.erase(it, entries.end());
    return true;
  }
  return false;
}

/**
 * Saves the vault in the file.
 *
 * const std::string& filename
 * const VaultHeader& header,
 * const VaultMeta& meta,
 * const std::vector<VaultEntry>& entries,
 * const std::vector<uint8_t>& key
 */
void Kleidos::saveVault(
  const std::string& filename,
  const VaultHeader& header,
  const VaultMeta& meta,
  const std::vector<VaultEntry>& entries,
  const std::vector<uint8_t>& key
  ) {
  // Serialize metadata
  auto metaBytes = serializeMeta(meta);

  // Serialize entries
  auto entryBytes = serializeEntries(entries);

  // Concatenate metadata + entries
  std::vector<uint8_t> plaintext;
  plaintext.reserve(metaBytes.size() + entryBytes.size());
  plaintext.insert(plaintext.end(), metaBytes.begin(), metaBytes.end());
  plaintext.insert(plaintext.end(), entryBytes.begin(), entryBytes.end());

  // Encrypt the full payload
  std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long clen;

  if (crypto_aead_chacha20poly1305_ietf_encrypt(
    ciphertext.data(), &clen,
    plaintext.data(), plaintext.size(),
    header.raw.data(), header.raw.size(),
    nullptr,
    header.nonce.data(),
    key.data()
  ) != 0) {
    throw std::runtime_error("Vault encryption failed");
  };

  // Write vault file
  overwriteVaultFile(filename, header.raw, ciphertext);
}
