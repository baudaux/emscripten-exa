#include "stdio_impl.h"

#ifdef __BB_DEBUG
#include <emscripten.h>
#endif

int __towrite(FILE *f)
{
	f->mode |= f->mode-1;
	if (f->flags & F_NOWR) {
		f->flags |= F_ERR;
		return EOF;
	}
	/* Clear read buffer (easier than summoning nasal demons) */
	f->rpos = f->rend = 0;

	/* Activate write through the buffer. */
	f->wpos = f->wbase = f->buf;
	f->wend = f->buf + f->buf_size;

#ifdef __BB_DEBUG
	// BB
	emscripten_log(EM_LOG_CONSOLE,"<-- __towrite wpos=%d wend=%d", f->wpos, f->wend);
#endif

	return 0;
}

hidden void __towrite_needs_stdio_exit()
{
	__stdio_exit_needed();
}
