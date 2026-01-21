#pragma once

#include "KleIncludes.h"
#include "Kleidos.h"

class KleInterface {
public:
  explicit KleInterface(Kleidos& kleidos);

  void run();

private:
  Kleidos& kleidos;

  void clearScreen();
  void pressEnterToContinue();

  void printMenu();
  int readMenuChoice();

  void listEntries(const std::vector<Kleidos::VaultEntry>& entries);
  void findEntry(const std::vector<Kleidos::VaultEntry>& entries);
  bool addEntryFlow(std::vector<Kleidos::VaultEntry>& entries);
  bool updateEntryFlow(std::vector<Kleidos::VaultEntry>& entries);
  bool removeEntryFlow(std::vector<Kleidos::VaultEntry>& entries);
};
