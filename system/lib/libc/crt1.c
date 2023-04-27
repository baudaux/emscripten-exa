/*
 * Copyright 2019 The Emscripten Authors.  All rights reserved.
 * Emscripten is available under two separate licenses, the MIT license and the
 * University of Illinois/NCSA Open Source License.  Both these licenses can be
 * found in the LICENSE file.
 */

#include <stdlib.h>
#include <wasi/api.h>

#include <unistd.h>
#include <emscripten.h>

#include "syscall.h"

__attribute__((__weak__)) void __wasm_call_ctors(void);

int __main_void(void);

static int ___main_argc_argv(int argc, char *argv[]) {

  return __main_void();
}

weak_alias(___main_argc_argv, __main_argc_argv);


//void _start(void) {
void _start(int argc, char *argv[]) {
  
  if (__wasm_call_ctors) {
    __wasm_call_ctors();
  }
  
  /*
   * Will either end up calling the user's original zero argument main directly
   * or our __original_main fallback in __original_main.c which handles
   * populating argv.
   */
  //int r = __main_void();

  //exit(r);
  exit(__main_argc_argv(argc, argv));
}

int exa_release_signal(int signum) {

  return __syscall(SYS_exa_release_signal, signum);
}

int exa_endofsignal(int signum) {

  return __syscall(SYS_exa_endofsignal, signum);
}

EMSCRIPTEN_KEEPALIVE void exa_signal_handler(void (*sig_handler)(int), int signum) {

  (*sig_handler)(signum);

  exa_release_signal(signum);
   
  exa_endofsignal(signum);
}
