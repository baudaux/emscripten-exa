#include <unistd.h>
#include "syscall.h"

//#include <emscripten.h>

int chdir(const char *path)
{
  // BB
  //emscripten_log(EM_LOG_CONSOLE, "musl: chdir %s", path);
  
	return syscall(SYS_chdir, path);
}
