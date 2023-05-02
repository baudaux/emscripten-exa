#include "stdio_impl.h"
#include <sys/ioctl.h>

//#include <emscripten.h>

size_t __stdout_write(FILE *f, const unsigned char *buf, size_t len)
{
  //emscripten_log(EM_LOG_CONSOLE,"__stdout_write: %d bytes (%d, lbf=%d)", len, f->flags & F_SVB, f->lbf);
  
	struct winsize wsz;
	f->write = __stdio_write;
	if (!(f->flags & F_SVB) && __syscall(SYS_ioctl, f->fd, TIOCGWINSZ, &wsz))
		f->lbf = -1;

	//emscripten_log(EM_LOG_CONSOLE,"__stdout_write: lbf=%d", f->lbf);
	
	return __stdio_write(f, buf, len);
}
