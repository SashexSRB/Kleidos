#include "Kleidos.h"
#include "KleInterface.h"

int main () {
  Kleidos vault;
  KleInterface app(vault);
  app.run();
  return 0;
}
