#include "Kleidos.h"
#include <print>
#include <iostream>
#include <cstring>

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
  std::println("Hello World!");
  auto mPass = Kleidos::promptMasterPassword();
  std::string passStr(mPass.begin(), mPass.end());
  std::println("{}", passStr);

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
