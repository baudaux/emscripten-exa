#include <poll.h>
#include <time.h>
#include <signal.h>
#include "syscall.h"

#include <emscripten.h>

int poll(struct pollfd *fds, nfds_t n, int timeout)
{
  emscripten_log(EM_LOG_CONSOLE, "--> poll n=%d timeout=%d", n, timeout);
  
#ifdef SYS_poll
  emscripten_log(EM_LOG_CONSOLE, "(2) --> poll n=%d timeout=%d", n, timeout);
  
	return syscall_cp(SYS_poll, fds, n, timeout);
#else
	return syscall_cp(SYS_ppoll, fds, n, timeout>=0 ?
		&((struct timespec){ .tv_sec = timeout/1000,
		.tv_nsec = timeout%1000*1000000 }) : 0, 0, _NSIG/8);
#endif
}
