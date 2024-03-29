#include <xboxrt/debug.h>
#include <pbkit/pbkit.h>
#include <hal/xbox.h>

class NumberClass{
private:
  int hiddenValue = 0;
public:
  NumberClass() {hiddenValue = 5;};
  NumberClass(int v) : hiddenValue(v) {};
  int getValue() { return hiddenValue; };
};

int main() {
  int ret = pb_init();
  if (ret != 0) {
    XSleep(2000);
    return -1;
  }

  pb_show_debug_screen();

  NumberClass defaultFive;
  NumberClass customSix(6);
  
  while (true) {
    debugPrint("Value of defaultFive: %i\n", defaultFive.getValue());
    debugPrint("Value of customSix  : %i\n", customSix.getValue());
    XSleep(2000);
  }

  pb_kill();

  return 0;
}
