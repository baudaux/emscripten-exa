#include <time.h>
#include "syscall.h"

#include <emscripten.h>

extern int emscripten_can_asyncify();

int nanosleep(const struct timespec *req, struct timespec *rem)
{
  /* Modified by Benoit Baudaux 7/09/2023 */
  if (emscripten_can_asyncify()) {
    
    return __syscall_ret(-__clock_nanosleep(CLOCK_REALTIME, 0, req, rem));
  }

  return 0;
}
