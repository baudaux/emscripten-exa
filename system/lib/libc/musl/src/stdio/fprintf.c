#include "stdio_impl.h"
#include <stdio.h>
#include <stdarg.h>

#include <emscripten.h>

int fprintf(FILE *restrict f, const char *restrict fmt, ...)
{
  //emscripten_log(EM_LOG_CONSOLE,"--> fprintf");
  
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = vfprintf(f, fmt, ap);
	va_end(ap);
	return ret;
}

// XXX EMSCRIPTEN
int fiprintf(FILE *restrict f, const char *restrict fmt, ...)
{
  //emscripten_log(EM_LOG_CONSOLE,"--> fiprintf");
  
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = vfiprintf(f, fmt, ap);
	va_end(ap);
	return ret;
}

int __small_fprintf(FILE *restrict f, const char *restrict fmt, ...)
{
  //emscripten_log(EM_LOG_CONSOLE,"--> __small_fprintf");
  
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = __small_vfprintf(f, fmt, ap);
	va_end(ap);
	return ret;
}
