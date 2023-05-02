#include "stdio_impl.h"
#include <string.h>

#include <emscripten.h>

size_t __fwritex(const unsigned char *restrict s, size_t l, FILE *restrict f)
{
  //emscripten_log(EM_LOG_CONSOLE, "--> __fwritex: %s l=%d", s, l);
  
	size_t i=0;

	if (!f->wend && __towrite(f)) return 0;

	//emscripten_log(EM_LOG_CONSOLE, "__fwritex 2: wend=%d wpos=%d", f->wend, f->wpos);

	if (l > f->wend - f->wpos) return f->write(f, s, l);

	//emscripten_log(EM_LOG_CONSOLE, "__fwritex 3");

	if (f->lbf >= 0) {
		/* Match /^(.*\n|)/ */
		for (i=l; i && s[i-1] != '\n'; i--);
		if (i) {
			size_t n = f->write(f, s, i);
			if (n < i) return n;
			s += i;
			l -= i;
		}
	}

	//emscripten_log(EM_LOG_CONSOLE, "__fwritex 4");

	memcpy(f->wpos, s, l);
	f->wpos += l;

	//emscripten_log(EM_LOG_CONSOLE, "__fwritex 5: wend=%d wpos=%d", f->wend, f->wpos);
	
	return l+i;
}

size_t fwrite(const void *restrict src, size_t size, size_t nmemb, FILE *restrict f)
{
	size_t k, l = size*nmemb;
	if (!size) nmemb = 0;
	FLOCK(f);
	k = __fwritex(src, l, f);
	FUNLOCK(f);
	return k==l ? nmemb : k/size;
}

weak_alias(fwrite, fwrite_unlocked);
