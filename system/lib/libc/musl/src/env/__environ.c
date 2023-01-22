#include <unistd.h>

char **__environ = 0;
weak_alias(__environ, ___environ);
weak_alias(__environ, _environ);
weak_alias(__environ, environ);

#ifdef __EMSCRIPTEN__
#include <stdlib.h>
#include <wasi/api.h>
#include <emscripten/heap.h>

#include <emscripten.h>

/* Modified by Benoit Baudaux 22/1/2023 */

EM_JS(int, environ_get_count, (), {

    if (Module['env']) {

      return Module['env'].count;
    }

    return 0;
});

EM_JS(int, environ_get_buf_size, (), {

    if (Module['env']) {

      return Module['env'].size;
    }

    return 0;
});

EM_JS(void, environ_get, (char ** env, char * buf), {

    if (Module['env']) {
      
      Module.HEAPU8.set(Module['env'].buf, buf);

      let count = 0;

      for (let i = 0; i < Module['env'].size;) {

	if (count >= Module['env'].count)
	  break;

	Module.HEAPU8[env+4*count] = (buf+i) & 0xff;
	Module.HEAPU8[env+4*count+1] = ((buf+i) >> 8) & 0xff;
	Module.HEAPU8[env+4*count+2] = ((buf+i) >> 16) & 0xff;
	Module.HEAPU8[env+4*count+3] = ((buf+i) >> 24) & 0xff;

	let j = 0;
	
	for (; Module.HEAPU8[buf+i+j]; j++) ;

	i += j+1;

	count++;
      }
    }
});

// We use emscripten_builtin_malloc here because this memory is never freed and
// and we don't want LSan to consider this a leak.
__attribute__((constructor(100))) // construct this before user code
void __emscripten_environ_constructor(void) {

  /* Modified by Benoit Baudaux 22/1/2023 */

  // Function called when "environ" is accessed in user app

  size_t environ_count;
    size_t environ_buf_size;

    environ_count = environ_get_count();

    environ_buf_size = environ_get_buf_size();

    
    /*__wasi_errno_t err = __wasi_environ_sizes_get(&environ_count,
                                                  &environ_buf_size);
    if (err != __WASI_ERRNO_SUCCESS) {
        return;
	}*/

    __environ = emscripten_builtin_malloc(sizeof(char *) * (environ_count + 1));
    if (__environ == 0) {
        return;
    }
    char * environ_buf = emscripten_builtin_malloc(sizeof(char) * environ_buf_size);
    if (environ_buf == 0) {
        __environ = 0;
        return;
    }

    // Ensure null termination.
    __environ[environ_count] = 0;

    /*err = __wasi_environ_get((uint8_t**)__environ, environ_buf);
    if (err != __WASI_ERRNO_SUCCESS) {
        __environ = 0;
	}*/

    if (environ_count > 0)
      environ_get(__environ, environ_buf);
}
  
#endif
