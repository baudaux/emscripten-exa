#include "stdio_impl.h"

//BB
#include <emscripten.h>

void rewind(FILE *f)
{
  //BB
	emscripten_log(EM_LOG_CONSOLE, "**** rewind");
	
	FLOCK(f);
	__fseeko_unlocked(f, 0, SEEK_SET);
	f->flags &= ~F_ERR;
	FUNLOCK(f);
}
