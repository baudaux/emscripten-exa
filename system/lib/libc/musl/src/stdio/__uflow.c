#include "stdio_impl.h"

//BB
#include <emscripten.h>

/* This function assumes it will never be called if there is already
 * data buffered for reading. */

int __uflow(FILE *f)
{
  //BB
  emscripten_log(EM_LOG_CONSOLE, "--> __uflow");
  
	unsigned char c;
	if (!__toread(f) && f->read(f, &c, 1)==1) return c;
	return EOF;
}
