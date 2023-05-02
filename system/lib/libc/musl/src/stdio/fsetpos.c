#include "stdio_impl.h"

//BB
#include <emscripten.h>

int fsetpos(FILE *f, const fpos_t *pos)
{
  //BB
  //emscripten_log(EM_LOG_CONSOLE, "**** fsetpos: %d", *(const long long *)pos);
	
	return __fseeko(f, *(const long long *)pos, SEEK_SET);
}

weak_alias(fsetpos, fsetpos64);
