#include <stdio_impl.h>

//BB
#include <emscripten.h>

int __toread(FILE *f)
{
   //BB
  emscripten_log(EM_LOG_CONSOLE, "__toread: wpos=%d wbase=%d", f->wpos, f->wbase);
  
	f->mode |= f->mode-1;
	if (f->wpos != f->wbase) f->write(f, 0, 0);

	//BB
  emscripten_log(EM_LOG_CONSOLE, "__toread: after fwrite wpos=%d wbase=%d", f->wpos, f->wbase);
  
	f->wpos = f->wbase = f->wend = 0;
	if (f->flags & F_NORD) {
		f->flags |= F_ERR;
		return EOF;
	}
	f->rpos = f->rend = f->buf + f->buf_size;

	//BB
  emscripten_log(EM_LOG_CONSOLE, "__toread: after fwrite rpos=%d flags=%x", f->rpos, f->flags);
	
	return (f->flags & F_EOF) ? EOF : 0;
}

hidden void __toread_needs_stdio_exit()
{
	__stdio_exit_needed();
}
