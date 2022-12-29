#include "stdio_impl.h"

int __overflow(FILE *f, int _c)
{

	unsigned char c = _c;
	if (!f->wend && __towrite(f)) return EOF;

#ifdef __BB_DEBUG
  	// BB
  	fprintf(stderr,"__overflow: %d; %d; %d\n",_c,f->wpos,f->wend);
#endif

	if (f->wpos != f->wend && c != f->lbf) return *f->wpos++ = c;
	if (f->write(f, &c, 1)!=1) return EOF;
	return c;
}
