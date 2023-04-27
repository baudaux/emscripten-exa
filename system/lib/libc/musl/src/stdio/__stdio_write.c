#include "stdio_impl.h"
#include <sys/uio.h>

/* Modified by Benoit Baudaux 5/1/2023 */
#undef __EMSCRIPTEN__

//
#include <emscripten.h>

size_t __stdio_write(FILE *f, const unsigned char *buf, size_t len)
{
	struct iovec iovs[2] = {
		{ .iov_base = f->wbase, .iov_len = f->wpos-f->wbase },
		{ .iov_base = (void *)buf, .iov_len = len }
	};

	struct iovec *iov = iovs;
	size_t rem = iov[0].iov_len + iov[1].iov_len;
	int iovcnt = 2;

#ifdef __BB_DEBUG
	// BB
	emscripten_log(EM_LOG_CONSOLE,"__stdio_write: %d;%d;%d",iov[0].iov_len,iov[1].iov_len,buf[0]);
#endif
	
	
	ssize_t cnt;
	for (;;) {
#if __EMSCRIPTEN__EXA
		size_t num;
		if (__wasi_syscall_ret(__wasi_fd_write(f->fd, (struct __wasi_ciovec_t*)iov, iovcnt, &num))) {
			num = -1;
		}
		cnt = num;
#else
		cnt = syscall(SYS_writev, f->fd, iov, iovcnt);
#endif
		if (cnt == rem) {
			f->wend = f->buf + f->buf_size;
			f->wpos = f->wbase = f->buf;
			return len;
		}
		if (cnt < 0) {
			f->wpos = f->wbase = f->wend = 0;
			f->flags |= F_ERR;
			return iovcnt == 2 ? 0 : len-iov[0].iov_len;
		}
		rem -= cnt;
		if (cnt > iov[0].iov_len) {
			cnt -= iov[0].iov_len;
			iov++; iovcnt--;
		}
		iov[0].iov_base = (char *)iov[0].iov_base + cnt;
		iov[0].iov_len -= cnt;
	}
}
