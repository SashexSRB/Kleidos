#include "KleInterface.h"

KleInterface::KleInterface(Kleidos& kleidos)
  : kleidos(kleidos) {}

void KleInterface::clearScreen() {
  std::cout << "\033[2J\033[H";
}

void KleInterface::pressEnterToContinue() {
  std::cout << "\nPress Enter to continue...";
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void KleInterface::printMenu() {
  std::cout << "\nWelcome to Kleidos.\n"
            << "1) List entries\n"
            << "2) Find entry\n"
            << "3) Add entry\n"
            << "4) Update entry\n"
            << "5) Remove entry\n"
            << "6) Exit\n"
            << "Choice: ";
}

int KleInterface::readMenuChoice() {
  std::string line;
  std::getline(std::cin, line);

  try {
    return std::stoi(line);
  } catch (...) {
    return -1;
  }
}

void KleInterface::listEntries(const std::vector<Kleidos::VaultEntry>& entries) {
  if (entries.empty()) {
    std::cout << "No entries in vault.\n";
  } else {
    for (const auto& e : entries) {
      std::cout << e.key << ": " << e.value << "\n";
    }
  }
  pressEnterToContinue();
}

void KleInterface::findEntry(const std::vector<Kleidos::VaultEntry>& entries) {
  if (entries.empty()) {
    std::cout << "No entries in fault.\n";
    pressEnterToContinue();
    return;
  }

  std::string key;
  std::cout << "Enter key: ";
  std::getline(std::cin, key);

  for (const auto& e : entries) {
    if (key == e.key) {
      std::cout << e.key << ": " << e.value << "\n";
      pressEnterToContinue();
      return;
    }
  }

  std::cout << "Key not found.\n";
  pressEnterToContinue();
}

bool KleInterface::addEntryFlow(std::vector<Kleidos::VaultEntry>& entries) {
  std::string key, value;

  std::cout << "Enter key: ";
  std::getline(std::cin, key);

  std::cout << "Enter value: ";
  std::getline(std::cin, value);

  kleidos.addEntry(entries, key, value);
  std::cout << "Entry added.\n";

  pressEnterToContinue();
  return true;
}

bool KleInterface::updateEntryFlow(std::vector<Kleidos::VaultEntry>& entries) {
  std::string key, value;

  std::cout << "Enter key: ";
  std::getline(std::cin, key),

  std::cout << "Enter value: ";
  std::getline(std::cin, value);

  if (kleidos.updateEntry(entries, key, value)) {
    std::cout << "Entry updated.\n";
    pressEnterToContinue();
    return true;
  }

  std::cout << "Key not found.\n";
  pressEnterToContinue();
  return false;
}

bool KleInterface::removeEntryFlow(std::vector<Kleidos::VaultEntry>& entries) {
  std::string key;

  std::cout << "Enter key to remove: ";
  std::getline(std::cin, key);

  if (kleidos.removeEntry(entries, key)) {
    std::cout << "Entry removed.\n";
    pressEnterToContinue();
    return true;
  }

  std::cout << "Key not found.\n";
  pressEnterToContinue();
  return false;
}

void KleInterface::run() {
  clearScreen();

  const std::string vaultFile = kleidos.getVaultPath();

  if (!std::ifstream(vaultFile, std::ios::binary).good()) {
    kleidos.init();
    if (!std::ifstream(vaultFile, std::ios::binary).good()) {
      throw std::runtime_error("Failed ot open vault file after init");
    }
  }

  auto pass = kleidos.promptMasterPassword();
  auto vault = kleidos.unlockCore(vaultFile, pass);

  bool running = true;
  while (running) {
    clearScreen();
    printMenu();

    const int choice = readMenuChoice();
    bool modified = false;

    switch (choice) {
      case 1: 
        listEntries(vault.entries);
        break;
      case 2:
        findEntry(vault.entries);
        break;
      case 3:
        modified = addEntryFlow(vault.entries);
        break;
      case 4:
        modified = updateEntryFlow(vault.entries);
        break;
      case 5:
        modified = removeEntryFlow(vault.entries);
        break;
      case 6:
        running = false;
        break;
      default:
        std::cout << "Invalid choice.\n";
        pressEnterToContinue();
    }

    if (modified) {
      kleidos.saveVault(vaultFile, vault.header, vault.meta, vault.entries, vault.key);
    }
  }

  sodium_memzero(vault.key.data(), vault.key.size());
  sodium_memzero(pass.data(), pass.size());

  std::cout << "Exiting Kleidos.\n";
  clearScreen();
}


