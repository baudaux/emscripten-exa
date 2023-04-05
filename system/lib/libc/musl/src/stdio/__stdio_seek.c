#include "stdio_impl.h"
#include <unistd.h>

//
#include <emscripten.h>

off_t __stdio_seek(FILE *f, off_t off, int whence)
{
  emscripten_log(EM_LOG_CONSOLE, "**** __stdio_seek: offset=%d, whence=%d", off, whence);
  
	return __lseek(f->fd, off, whence);
}
