#include <stdlib.h>
#include "syscall.h"

_Noreturn void _Exit(int ec)
{
  /* Modified by Benoit Baudaux 28/03/2023 */
#ifdef __EMSCRIPTEN__EXA
	__wasi_proc_exit(ec);
#else
	
	__syscall(SYS_exit_group, ec);
	for (;;) __syscall(SYS_exit, ec);
#endif
}
