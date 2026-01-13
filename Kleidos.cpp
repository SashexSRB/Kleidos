#include "Kleidos.h"
#include <print>
#include <iostream>
#include <cstring>

void Kleidos::init() {
  std::println("Hello World!");
  auto mPass = Kleidos::promptMasterPassword();
  std::string passStr(mPass.begin(), mPass.end());
  std::println("{}", passStr);

  std::memset(mPass.data(), 0, mPass.size());
}

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
