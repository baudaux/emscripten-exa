/**
 * @license
 * Copyright 2010 The Emscripten Authors
 * SPDX-License-Identifier: MIT
 */

// === Auto-generated postamble setup entry stuff ===

{{{ exportRuntime() }}}

#if !MEM_INIT_IN_WASM
function runMemoryInitializer() {
#if USE_PTHREADS
  if (!memoryInitializer || ENVIRONMENT_IS_PTHREAD) return;
#else
  if (!memoryInitializer) return
#endif
  if (!isDataURI(memoryInitializer)) {
    memoryInitializer = locateFile(memoryInitializer);
  }
  if (ENVIRONMENT_IS_NODE || ENVIRONMENT_IS_SHELL) {
    var data = readBinary(memoryInitializer);
    HEAPU8.set(data, {{{ GLOBAL_BASE }}});
  } else {
    addRunDependency('memory initializer');
    var applyMemoryInitializer = (data) => {
      if (data.byteLength) data = new Uint8Array(data);
#if ASSERTIONS
      for (var i = 0; i < data.length; i++) {
        assert(HEAPU8[{{{ GLOBAL_BASE }}} + i] === 0, "area for memory initializer should not have been touched before it's loaded");
      }
#endif
      HEAPU8.set(data, {{{ GLOBAL_BASE }}});
      // Delete the typed array that contains the large blob of the memory initializer request response so that
      // we won't keep unnecessary memory lying around. However, keep the XHR object itself alive so that e.g.
      // its .status field can still be accessed later.
      if (Module['memoryInitializerRequest']) delete Module['memoryInitializerRequest'].response;
      removeRunDependency('memory initializer');
    };
    var doBrowserLoad = () => {
      readAsync(memoryInitializer, applyMemoryInitializer, function() {
        var e = new Error('could not load memory initializer ' + memoryInitializer);
#if MODULARIZE
          readyPromiseReject(e);
#else
          throw e;
#endif
      });
    };
#if SUPPORT_BASE64_EMBEDDING
    var memoryInitializerBytes = tryParseAsDataURI(memoryInitializer);
    if (memoryInitializerBytes) {
      applyMemoryInitializer(memoryInitializerBytes.buffer);
    } else
#endif
    if (Module['memoryInitializerRequest']) {
      // a network request has already been created, just use that
      var useRequest = () => {
        var request = Module['memoryInitializerRequest'];
        var response = request.response;
        if (request.status !== 200 && request.status !== 0) {
#if SUPPORT_BASE64_EMBEDDING
          var data = tryParseAsDataURI(Module['memoryInitializerRequestURL']);
          if (data) {
            response = data.buffer;
          } else {
#endif
            // If you see this warning, the issue may be that you are using locateFile and defining it in JS. That
            // means that the HTML file doesn't know about it, and when it tries to create the mem init request early, does it to the wrong place.
            // Look in your browser's devtools network console to see what's going on.
            console.warn('a problem seems to have happened with Module.memoryInitializerRequest, status: ' + request.status + ', retrying ' + memoryInitializer);
            doBrowserLoad();
            return;
#if SUPPORT_BASE64_EMBEDDING
          }
#endif
        }
        applyMemoryInitializer(response);
      };
      if (Module['memoryInitializerRequest'].response) {
        setTimeout(useRequest, 0); // it's already here; but, apply it asynchronously
      } else {
        Module['memoryInitializerRequest'].addEventListener('load', useRequest); // wait for it
      }
    } else {
      // fetch it from the network ourselves
      doBrowserLoad();
    }
  }
}
#endif // MEM_INIT_IN_WASM == 0

var calledRun;

#if STANDALONE_WASM && MAIN_READS_PARAMS
var mainArgs = undefined;
#endif

dependenciesFulfilled = function runCaller() {

    // Added by Benoit Baudaux 20/1/2023

    if (ENVIRONMENT_IS_WEB) {
	
	//console.log = function() {};
	
	Module['fd_table'] = {};
	Module['fd_table'].last_fd = 2;

	Module['bc_channels'] = {};
	Module['get_broadcast_channel'] = (name) => {

	    if (name in Module['bc_channels']) {
		return Module['bc_channels'][name];
	    }
	    else {

		Module['bc_channels'][name] = new BroadcastChannel(name);
		return Module['bc_channels'][name];
	    }
	};

	Module['rcv_bc_channel'] = new BroadcastChannel("channel.process."+window.frameElement.getAttribute('pid'));

	Module['rcv_bc_channel'].handlers = [];
	Module['rcv_bc_channel'].id = 0;
	Module['rcv_bc_channel'].events = [];
	
	//console.log("rcv_bc_channel created");

	Module['rcv_bc_channel'].default_handler = (messageEvent) => {

	    /*if (Module['rcv_bc_channel'].handlers && (Module['rcv_bc_channel'].handlers.length > 1) ) {

		debugger;
	    }*/

	    let msg = messageEvent.data;

	    //console.log(msg.buf);

	    if (msg.buf[0] == 42) {  // KILL

		let signum = msg.buf[16] | (msg.buf[17] << 8) | (msg.buf[18] << 16) |  (msg.buf[18] << 24);

		let sig_handler = msg.buf[20] | (msg.buf[21] << 8) | (msg.buf[22] << 16) |  (msg.buf[23] << 24);

		if (sig_handler) {

		    Asyncify.stackTop = stackSave();
		    Asyncify.stackBase = _emscripten_stack_get_base();
		    Asyncify.stackEnd = _emscripten_stack_get_end();

		    savedAsyncify = JSON.stringify(Asyncify);

		    _exa_signal_handler(sig_handler, signum);

		    return;
		}
	    }
	    
	    if (Module['rcv_bc_channel'].handlers && (Module['rcv_bc_channel'].handlers.length > 0) ) {

		

		let ret = Module['rcv_bc_channel'].handlers[Module['rcv_bc_channel'].handlers.length-1].handler(messageEvent);

		if (ret > 0) {
		    Module['rcv_bc_channel'].unset_handler(ret);
		}
		else {
		    
		    //console.log("!!!!!! Push event !! "+messageEvent.data.buf[0]+", "+Module['rcv_bc_channel'].handlers.length);
		    
		    Module['rcv_bc_channel'].events.push(messageEvent);
		}
	    }
	};

	Module['rcv_bc_channel'].set_handler = (handler) => {

	    if (handler) {

		Module['rcv_bc_channel'].id += 1;
		
		Module['rcv_bc_channel'].handlers.push(
		    {
			id: Module['rcv_bc_channel'].id,
			handler: handler
		    }
		);

		return Module['rcv_bc_channel'].id;
	    }

	    return -1;
	};
	
	Module['rcv_bc_channel'].unset_handler = (id) => {

	    //console.log("!!!!!! unset_handler "+id+" len="+Module['rcv_bc_channel'].handlers.length);

	    let handler_removed = 0;
	    
	    for (let i = 0; i < Module['rcv_bc_channel'].handlers.length; i++) {

		if (Module['rcv_bc_channel'].handlers[i].id == id) {

		    Module['rcv_bc_channel'].handlers.splice(i, 1);
		    handler_removed = 1;
		    break;
		}
	    }

	    if (!handler_removed) {

		//console.log("!!!!!! CANNOT REMOVE HANDLER !!!!!!!");
		//debugger;
	    }
	};

	Module['rcv_bc_channel'].onmessage = Module['rcv_bc_channel'].default_handler;

	Module.getpid = function() {

	    let pid = Module.pid;

	    if (pid)
		return pid;

	    if ( ('PThread' in Module) && Module['PThread'].tid) {
		
		pid = Module['PThread'].tid;

		if ( (pid & 0xffff0000) == 0x00010000) // main thread
		    pid = pid & 0xffff;
	    }
	    else {
		pid = parseInt(window.frameElement.getAttribute('pid'));
	    }

	    Module.pid = pid;

	    return pid;
	};
	
	// Added by Benoit Baudaux 02/12/2022
	if (window.name == "child") {

	    let channel = 'channel.1.'+window.frameElement.getAttribute('pid')+'.fork';

	    if (!Module[channel]) {

		Module[channel] = new BroadcastChannel('channel.1.'+window.frameElement.getAttribute('pid')+'.fork');

		Module[channel].onmessage = (function(_ch) {

		    return ((messageEvent) => {

			if (messageEvent.data.length > 1024) {

			    #if STACK_OVERFLOW_CHECK
			    stackCheckInit();
			    #endif
			    
			    preRun();
			    
			    Module['calledRun'] = true;
			    
			    initRuntime();
			    
			    preMain();

			    Module.HEAPU8.set(messageEvent.data);
			}
			else {

			    var a = JSON.parse(messageEvent.data);
			    
			    Asyncify.callStackId = a.callStackId;
			    Asyncify.callStackIdToName = a.callStackIdToName;
			    Asyncify.callStackNameToId = a.callStackNameToId;
			    Asyncify.currData = a.currData;
			    Asyncify.handleSleepReturnValue = 0;// 0 is return from fork in child process
			    Asyncify.state = a.state;
			    Asyncify.exportCallStack = a.exportCallStack;
			    
			    _emscripten_stack_set_limits(a.stackBase,a.stackEnd);
			    stackRestore(a.stackTop);

			    Module[_ch].postMessage("end_fork");

			    Module[_ch] = null;
			    
			    // Start child
			    
			    Asyncify.state = Asyncify.State.Rewinding;
			    
			    runAndAbortIfError(() => Module['_asyncify_start_rewind'](Asyncify.currData));
			    
			    var asyncWasmReturnValue, isError = false;
			    try {
				asyncWasmReturnValue = Asyncify.doRewind(Asyncify.currData);
				
			    } catch (err) {
				
				console.log(err);
				//debugger;
				
				asyncWasmReturnValue = err;
				isError = true;
			    }
			    // Track whether the return value was handled by any promise handlers.
			    var handled = false;
			    if (!Asyncify.currData) {
				// All asynchronous execution has finished.
				// `asyncWasmReturnValue` now contains the final
				// return value of the exported async WASM function.
				//
				// Note: `asyncWasmReturnValue` is distinct from
				// `Asyncify.handleSleepReturnValue`.
				// `Asyncify.handleSleepReturnValue` contains the return
				// value of the last C function to have executed
				// `Asyncify.handleSleep()`, where as `asyncWasmReturnValue`
				// contains the return value of the exported WASM function
				// that may have called C functions that
				// call `Asyncify.handleSleep()`.
				var asyncPromiseHandlers = Asyncify.asyncPromiseHandlers;
				if (asyncPromiseHandlers) {
				    Asyncify.asyncPromiseHandlers = null;
				    (isError ? asyncPromiseHandlers.reject : asyncPromiseHandlers.resolve)(asyncWasmReturnValue);
				    handled = true;
				}
			    }
			}
		    });
		})(channel);

		//console.log("Sending continue_fork on "+window.frameElement.getAttribute('pid'));

		Module[channel].postMessage("continue_fork");
		
		return;
	    }
	}
	// Added by Benoit Baudaux 20/1/2023
	else if (window.name == "exec") {

	    //console.log("From exec: need to get back args and env");

	    let buf_size = 1256;

	    let buf = new Uint8Array(buf_size);

	    buf[0] = 8; // EXECVE

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf[4] = pid & 0xff;
	    buf[5] = (pid >> 8) & 0xff;
	    buf[6] = (pid >> 16) & 0xff;
	    buf[7] = (pid >> 24) & 0xff;

	    // errno
	    buf[8] = 0;
	    buf[9] = 0;
	    buf[10] = 0;
	    buf[11] = 0;

	    // size
	    buf[12] = 0xff;
	    buf[13] = 0xff;
	    buf[14] = 0xff;
	    buf[15] = 0xff;

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (8|0x80)) {

		    //console.log("Return from exec: time to restore !!!!!");

		    //console.log(msg2.buf);

		    arguments_ = [];

		    let args_size = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

		    //console.log(args_size);

		    td = new TextDecoder("utf-8");

		    let i = 16;

		    for (; i < (16+args_size); ) {

			let j = 0;

			for (; msg2.buf[i+j]; j++) ;

			let a = msg2.buf.slice(i,i+j);

			arguments_.push(td.decode(a));

			i += j+1;
		    }

		    //console.log(arguments_);

		    let env_count = msg2.buf[i] | (msg2.buf[i+1] << 8) | (msg2.buf[i+2] << 16) |  (msg2.buf[i+3] << 24);

		    let env_size = msg2.buf[i+4] | (msg2.buf[i+5] << 8) | (msg2.buf[i+6] << 16) |  (msg2.buf[i+7] << 24);

		    Module['env'] = {

			count: env_count,
			size: env_size,
			buf : msg2.buf.slice(i+8,i+8+env_size)
		    };

		    //console.log(Module['env']);

		    //Module['rcv_bc_channel'].unset_handler(hid); // Handler is unset here, exception for exec
		    
		    // If run has never been called, and we should call run (INVOKE_RUN is true, and Module.noInitialRun is not false)
		    if (!calledRun) run();
		    if (!calledRun) dependenciesFulfilled = runCaller; // try this again later, after new deps are fulfilled

		    return hid;
		}
		else {

		    return -1;
		}
	    });

	    let msg = {
		
		from: Module['rcv_bc_channel'].name,
		buf: buf,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);

	    return;
	}

    }
    
  // If run has never been called, and we should call run (INVOKE_RUN is true, and Module.noInitialRun is not false)
  if (!calledRun) run();
  if (!calledRun) dependenciesFulfilled = runCaller; // try this again later, after new deps are fulfilled
};

#if HAS_MAIN
function callMain(args) {
#if ASSERTIONS
  assert(runDependencies == 0, 'cannot call main when async dependencies remain! (listen on Module["onRuntimeInitialized"])');
  assert(__ATPRERUN__.length == 0, 'cannot call main when preRun functions remain to be called');
#endif

#if STANDALONE_WASM
#if EXPECT_MAIN
  var entryFunction = Module['__start'];
#else
  var entryFunction = Module['__initialize'];
#endif
#else
#if PROXY_TO_PTHREAD
  // User requested the PROXY_TO_PTHREAD option, so call a stub main which pthread_create()s a new thread
  // that will call the user's real main() for the application.
  var entryFunction = Module['__emscripten_proxy_main'];
#else
    // Modified by Benoit Baudaux 29/03/2023
    var entryFunction;

    //BB

    if (ENVIRONMENT_IS_WEB) {

	entryFunction = Module['__start'];
    }
    else {
	entryFunction = Module['_main'];
    }
    
#endif
#endif

#if MAIN_MODULE
  // Main modules can't tell if they have main() at compile time, since it may
  // arrive from a dynamic library.
  if (!entryFunction) return;
#endif

#if MAIN_READS_PARAMS && STANDALONE_WASM
  mainArgs = [thisProgram].concat(args)
#elif MAIN_READS_PARAMS
  args = args || [];
  // Modified By Benoit Baudaux 14/11/2022
  //args.unshift(thisProgram);

  var argc = args.length;
  var argv = stackAlloc((argc + 1) * {{{ Runtime.POINTER_SIZE }}});
  var argv_ptr = argv >> {{{ POINTER_SHIFT }}};
  args.forEach((arg) => {
    {{{ POINTER_HEAP }}}[argv_ptr++] = {{{ to64('allocateUTF8OnStack(arg)') }}};
  });
  {{{ POINTER_HEAP }}}[argv_ptr] = {{{ to64('0') }}};
#else
  var argc = 0;
  var argv = 0;
#endif // MAIN_READS_PARAMS

#if ABORT_ON_WASM_EXCEPTIONS || !PROXY_TO_PTHREAD
  try {
#endif
#if BENCHMARK
    var start = Date.now();
#endif

#if ABORT_ON_WASM_EXCEPTIONS
    // See abortWrapperDepth in preamble.js!
    abortWrapperDepth += 1;
#endif

#if STANDALONE_WASM
    entryFunction();
    // _start (in crt1.c) will call exit() if main return non-zero.  So we know
    // that if we get here main returned zero.
    var ret = 0;
#else

      var ret = entryFunction(argc, {{{ to64('argv') }}});
      
#endif // STANDALONE_WASM

#if BENCHMARK
    Module.realPrint('main() took ' + (Date.now() - start) + ' milliseconds');
#endif

    // In PROXY_TO_PTHREAD builds, we should never exit the runtime below, as
    // execution is asynchronously handed off to a pthread.
#if PROXY_TO_PTHREAD
#if ASSERTIONS
    assert(ret == 0, '_emscripten_proxy_main failed to start proxy thread: ' + ret);
#endif
#if ABORT_ON_WASM_EXCEPTIONS
  }
#endif
#else
#if ASYNCIFY == 2
    // The current spec of JSPI returns a promise only if the function suspends
    // and a plain value otherwise. This will likely change:
    // https://github.com/WebAssembly/js-promise-integration/issues/11
    Promise.resolve(ret).then((result) => {
      exitJS(result, /* implicit = */ true);
    }).catch((e) => {
      handleException(e);
    });
#else
    // if we're not running an evented main loop, it's time to exit
    exitJS(ret, /* implicit = */ true);
#endif // ASYNCIFY == 2
    return ret;
  }
  catch (e) {
    return handleException(e);
  }
#endif // !PROXY_TO_PTHREAD
#if ABORT_ON_WASM_EXCEPTIONS
  finally {
    // See abortWrapperDepth in preamble.js!
    abortWrapperDepth -= 1;
  }
#endif
}
#endif // HAS_MAIN

#if STACK_OVERFLOW_CHECK
function stackCheckInit() {
  // This is normally called automatically during __wasm_call_ctors but need to
  // get these values before even running any of the ctors so we call it redundantly
  // here.
#if ASSERTIONS && USE_PTHREADS
  // See $establishStackSpace for the equivelent code that runs on a thread
  assert(!ENVIRONMENT_IS_PTHREAD);
#endif
#if RELOCATABLE
  _emscripten_stack_set_limits({{{ STACK_BASE }}} , {{{ STACK_MAX }}});
#else
  _emscripten_stack_init();
#endif
  // TODO(sbc): Move writeStackCookie to native to to avoid this.
  writeStackCookie();
}
#endif

#if RELOCATABLE
var dylibsLoaded = false;
#endif

/** @type {function(Array=)} */
function run(args) {
  args = args || arguments_;

  if (runDependencies > 0) {
#if RUNTIME_LOGGING
    err('run() called, but dependencies remain, so not running');
#endif
    return;
  }

#if STACK_OVERFLOW_CHECK
#if USE_PTHREADS
  if (!ENVIRONMENT_IS_PTHREAD)
#endif
    stackCheckInit();
#endif

#if RELOCATABLE
  if (!dylibsLoaded) {
  // Loading of dynamic libraries needs to happen on each thread, so we can't
  // use the normal __ATPRERUN__ mechanism.
#if MAIN_MODULE
    preloadDylibs();
#else
    reportUndefinedSymbols();
#endif
    dylibsLoaded = true;

    // Loading dylibs can add run dependencies.
    if (runDependencies > 0) {
#if RUNTIME_LOGGING
      err('preloadDylibs added run() dependencies, not running yet');
#endif
      return;
    }
  }
#endif

#if WASM_WORKERS
  if (ENVIRONMENT_IS_WASM_WORKER) {
#if MODULARIZE
    readyPromiseResolve(Module);
#endif // MODULARIZE
    return initRuntime();
  }
#endif

#if USE_PTHREADS
  if (ENVIRONMENT_IS_PTHREAD) {
#if MODULARIZE
    // The promise resolve function typically gets called as part of the execution
    // of `doRun` below. The workers/pthreads don't execute `doRun` so the
    // creation promise can be resolved, marking the pthread-Module as initialized.
    readyPromiseResolve(Module);
#endif // MODULARIZE
    initRuntime();
    postMessage({ 'cmd': 'loaded' });
    return;
  }
#endif

  preRun();

  // a preRun added a dependency, run will be called later
  if (runDependencies > 0) {
#if RUNTIME_LOGGING
    err('run() called, but dependencies remain, so not running');
#endif
    return;
  }

  function doRun() {
    // run may have just been called through dependencies being fulfilled just in this very frame,
    // or while the async setStatus time below was happening
    if (calledRun) return;
    calledRun = true;
    Module['calledRun'] = true;

      if (ABORT) return;

    initRuntime();

#if HAS_MAIN
    preMain();
#endif

#if MODULARIZE
    readyPromiseResolve(Module);
#endif
#if expectToReceiveOnModule('onRuntimeInitialized')
    if (Module['onRuntimeInitialized']) Module['onRuntimeInitialized']();
#endif

#if HAS_MAIN
    if (shouldRunNow) callMain(args);
#else
#if ASSERTIONS
    assert(!Module['_main'], 'compiled without a main, but one is present. if you added it from JS, use Module["onRuntimeInitialized"]');
#endif // ASSERTIONS
#endif // HAS_MAIN

    postRun();
  }

#if expectToReceiveOnModule('setStatus')
  if (Module['setStatus']) {
    Module['setStatus']('Running...');
    setTimeout(function() {
      setTimeout(function() {
        Module['setStatus']('');
      }, 1);
      doRun();
    }, 1);
  } else
#endif
  {
    doRun();
  }
#if STACK_OVERFLOW_CHECK
  checkStackCookie();
#endif
}

#if ASSERTIONS
#if EXIT_RUNTIME == 0
function checkUnflushedContent() {
  // Compiler settings do not allow exiting the runtime, so flushing
  // the streams is not possible. but in ASSERTIONS mode we check
  // if there was something to flush, and if so tell the user they
  // should request that the runtime be exitable.
  // Normally we would not even include flush() at all, but in ASSERTIONS
  // builds we do so just for this check, and here we see if there is any
  // content to flush, that is, we check if there would have been
  // something a non-ASSERTIONS build would have not seen.
  // How we flush the streams depends on whether we are in SYSCALLS_REQUIRE_FILESYSTEM=0
  // mode (which has its own special function for this; otherwise, all
  // the code is inside libc)
  var oldOut = out;
  var oldErr = err;
  var has = false;
  out = err = (x) => {
    has = true;
  }
  try { // it doesn't matter if it fails
#if SYSCALLS_REQUIRE_FILESYSTEM == 0 && '$flush_NO_FILESYSTEM' in addedLibraryItems
    flush_NO_FILESYSTEM();
#elif hasExportedSymbol('fflush')
    _fflush(0);
#endif
#if '$FS' in addedLibraryItems && '$TTY' in addedLibraryItems
    // also flush in the JS FS layer
    ['stdout', 'stderr'].forEach(function(name) {
      var info = FS.analyzePath('/dev/' + name);
      if (!info) return;
      var stream = info.object;
      var rdev = stream.rdev;
      var tty = TTY.ttys[rdev];
      if (tty && tty.output && tty.output.length) {
        has = true;
      }
    });
#endif
  } catch(e) {}
  out = oldOut;
  err = oldErr;
  if (has) {
    warnOnce('stdio streams had content in them that was not flushed. you should set EXIT_RUNTIME to 1 (see the FAQ), or make sure to emit a newline when you printf etc.');
#if FILESYSTEM == 0 || SYSCALLS_REQUIRE_FILESYSTEM == 0
    warnOnce('(this may also be due to not including full filesystem support - try building with -sFORCE_FILESYSTEM)');
#endif
  }
}
#endif // EXIT_RUNTIME
#endif // ASSERTIONS

#if expectToReceiveOnModule('preInit')
if (Module['preInit']) {
  if (typeof Module['preInit'] == 'function') Module['preInit'] = [Module['preInit']];
  while (Module['preInit'].length > 0) {
    Module['preInit'].pop()();
  }
}
#endif

#if HAS_MAIN
// shouldRunNow refers to calling main(), not run().
#if INVOKE_RUN
var shouldRunNow = true;
#else
var shouldRunNow = false;
#endif

#if expectToReceiveOnModule('noInitialRun')
if (Module['noInitialRun']) shouldRunNow = false;
#endif

#endif // HAS_MAIN

run();

#if BUILD_AS_WORKER

var workerResponded = false, workerCallbackId = -1;

(function() {
  var messageBuffer = null, buffer = 0, bufferSize = 0;

  function flushMessages() {
    if (!messageBuffer) return;
    if (runtimeInitialized) {
      var temp = messageBuffer;
      messageBuffer = null;
      temp.forEach(function(message) {
        onmessage(message);
      });
    }
  }

  function messageResender() {
    flushMessages();
    if (messageBuffer) {
      setTimeout(messageResender, 100); // still more to do
    }
  }

  onmessage = (msg) => {
    // if main has not yet been called (mem init file, other async things), buffer messages
    if (!runtimeInitialized) {
      if (!messageBuffer) {
        messageBuffer = [];
        setTimeout(messageResender, 100);
      }
      messageBuffer.push(msg);
      return;
    }
    flushMessages();

    var func = Module['_' + msg.data['funcName']];
    if (!func) throw 'invalid worker function to call: ' + msg.data['funcName'];
    var data = msg.data['data'];
    if (data) {
      if (!data.byteLength) data = new Uint8Array(data);
      if (!buffer || bufferSize < data.length) {
        if (buffer) _free(buffer);
        bufferSize = data.length;
        buffer = _malloc(data.length);
      }
      HEAPU8.set(data, buffer);
    }

    workerResponded = false;
    workerCallbackId = msg.data['callbackId'];
    if (data) {
      func(buffer, data.length);
    } else {
      func(0, 0);
    }
  }
})();

#endif

#if STANDALONE_WASM && ASSERTIONS && !WASM_BIGINT
err('warning: running JS from STANDALONE_WASM without WASM_BIGINT will fail if a syscall with i64 is used (in standalone mode we cannot legalize syscalls)');
#endif
