/**
 * @license
 * Copyright 2015 The Emscripten Authors
 * SPDX-License-Identifier: MIT
 */

var SyscallsLibrary = {
  $SYSCALLS__deps: [
#if FILESYSTEM && SYSCALLS_REQUIRE_FILESYSTEM
                   '$PATH',
                   '$FS',
#endif
#if SYSCALL_DEBUG
                   '$ERRNO_MESSAGES'
#endif
  ],
  $SYSCALLS: {
#if SYSCALLS_REQUIRE_FILESYSTEM
    // global constants
    DEFAULT_POLLMASK: {{{ cDefine('POLLIN') }}} | {{{ cDefine('POLLOUT') }}},

    // shared utilities
    calculateAt: function(dirfd, path, allowEmpty) {
      if (PATH.isAbs(path)) {
        return path;
      }
      // relative path
      var dir;
      if (dirfd === {{{ cDefine('AT_FDCWD') }}}) {
        dir = FS.cwd();
      } else {
        var dirstream = SYSCALLS.getStreamFromFD(dirfd);
        dir = dirstream.path;
      }
      if (path.length == 0) {
        if (!allowEmpty) {
          throw new FS.ErrnoError({{{ cDefine('ENOENT') }}});;
        }
        return dir;
      }
      return PATH.join2(dir, path);
    },

    doStat: function(func, path, buf) {
      try {
        var stat = func(path);
      } catch (e) {
        if (e && e.node && PATH.normalize(path) !== PATH.normalize(FS.getPath(e.node))) {
          // an error occurred while trying to look up the path; we should just report ENOTDIR
          return -{{{ cDefine('ENOTDIR') }}};
        }
        throw e;
      }
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_dev, 'stat.dev', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.__st_ino_truncated, 'stat.ino', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_mode, 'stat.mode', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_nlink, 'stat.nlink', SIZE_TYPE) }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_uid, 'stat.uid', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_gid, 'stat.gid', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_rdev, 'stat.rdev', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_size, 'stat.size', 'i64') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_blksize, '4096', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_blocks, 'stat.blocks', 'i32') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_atim.tv_sec, 'Math.floor(stat.atime.getTime() / 1000)', 'i64') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_atim.tv_nsec, '0', SIZE_TYPE) }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_mtim.tv_sec, 'Math.floor(stat.mtime.getTime() / 1000)', 'i64') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_mtim.tv_nsec, '0', SIZE_TYPE) }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_ctim.tv_sec, 'Math.floor(stat.ctime.getTime() / 1000)', 'i64') }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_ctim.tv_nsec, '0', SIZE_TYPE) }}};
      {{{ makeSetValue('buf', C_STRUCTS.stat.st_ino, 'stat.ino', 'i64') }}};
      return 0;
    },
    doMsync: function(addr, stream, len, flags, offset) {
      if (!FS.isFile(stream.node.mode)) {
        throw new FS.ErrnoError({{{ cDefine('ENODEV') }}});
      }
      if (flags & {{{ cDefine('MAP_PRIVATE') }}}) {
        // MAP_PRIVATE calls need not to be synced back to underlying fs
        return 0;
      }
#if CAN_ADDRESS_2GB
      addr >>>= 0;
#endif
      var buffer = HEAPU8.slice(addr, addr + len);
      FS.msync(stream, buffer, offset, len, flags);
    },
#endif

    // arguments handling

    varargs: undefined,

    get: function() {
#if ASSERTIONS
      assert(SYSCALLS.varargs != undefined);
#endif
      SYSCALLS.varargs += 4;
      var ret = {{{ makeGetValue('SYSCALLS.varargs', '-4', 'i32') }}};
#if SYSCALL_DEBUG
      dbg('    (raw: "' + ret + '")');
#endif
      return ret;
    },
    getStr: function(ptr) {
      var ret = UTF8ToString(ptr);
#if SYSCALL_DEBUG
      dbg('    (str: "' + ret + '")');
#endif
      return ret;
    },
#if SYSCALLS_REQUIRE_FILESYSTEM
    // Just like `FS.getStream` but will throw EBADF if stream is undefined.
    getStreamFromFD: function(fd) {
      var stream = FS.getStream(fd);
      if (!stream) throw new FS.ErrnoError({{{ cDefine('EBADF') }}});
#if SYSCALL_DEBUG
      dbg('    (stream: "' + stream.path + '")');
#endif
      return stream;
    },
#endif // SYSCALLS_REQUIRE_FILESYSTEM
  },

  _mmap_js__sig: 'ipiiippp',
  _mmap_js__deps: ['$SYSCALLS',
#if FILESYSTEM && SYSCALLS_REQUIRE_FILESYSTEM
    '$FS',
#endif
  ],
  _mmap_js: function(len, prot, flags, fd, off, allocated, addr) {
#if FILESYSTEM && SYSCALLS_REQUIRE_FILESYSTEM
    var stream = SYSCALLS.getStreamFromFD(fd);
    var res = FS.mmap(stream, len, off, prot, flags);
    var ptr = res.ptr;
    {{{ makeSetValue('allocated', 0, 'res.allocated', 'i32') }}};
#if CAN_ADDRESS_2GB
    ptr >>>= 0;
#endif
    {{{ makeSetValue('addr', 0, 'ptr', '*') }}};
    return 0;
#else // no filesystem support; report lack of support
    return -{{{ cDefine('ENOSYS') }}};
#endif
  },

  _munmap_js__deps: ['$SYSCALLS',
#if FILESYSTEM && SYSCALLS_REQUIRE_FILESYSTEM
    '$FS',
#endif
  ],
  _munmap_js__sig: 'ippiiip',
  _munmap_js: function(addr, len, prot, flags, fd, offset) {
#if FILESYSTEM && SYSCALLS_REQUIRE_FILESYSTEM
    var stream = SYSCALLS.getStreamFromFD(fd);
    if (prot & {{{ cDefine('PROT_WRITE') }}}) {
      SYSCALLS.doMsync(addr, stream, len, flags, offset);
    }
    FS.munmap(stream);
    // implicitly return 0
#endif
  },

  __syscall_chdir__sig: 'ip',
    __syscall_chdir: function(path) {

	//console.log("library_syscall.js: __syscall_chdir");

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 1256;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 35; // CHDIR

	    /*//padding
	      buf[1] = 0;
	      buf[2] = 0;
	      buf[3] = 0;*/

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    let path_len = 0;

	    while (Module.HEAPU8[path+path_len]) {

		path_len++;
	    }

	    path_len++;

	    buf2[12] = path_len & 0xff;
	    buf2[13] = (path_len >> 8) & 0xff;
	    buf2[14] = (path_len >> 16) & 0xff;
	    buf2[15] = (path_len >> 24) & 0xff;

	    buf2.set(Module.HEAPU8.slice(path, path+path_len), 16);
	    
	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);
		
		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (35|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_stat64: _errno="+_errno);

		    wakeUp(-_errno);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: 1256
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");
	    
	    bc.postMessage(msg);

	});

	return ret;
	
    /*path = SYSCALLS.getStr(path);
    FS.chdir(path);
    return 0;*/
  },
  __syscall_chmod__sig: 'ipi',
  __syscall_chmod: function(path, mode) {
    path = SYSCALLS.getStr(path);
    FS.chmod(path, mode);
    return 0;
  },
  __syscall_rename__sig: 'ipp',
  __syscall_rename: function(old_path, new_path) {
    old_path = SYSCALLS.getStr(old_path);
    new_path = SYSCALLS.getStr(new_path);
    FS.rename(old_path, new_path);
    return 0;
  },
  __syscall_rmdir__sig: 'ip',
  __syscall_rmdir: function(path) {
    path = SYSCALLS.getStr(path);
    FS.rmdir(path);
    return 0;
  },
  __syscall_dup__sig: 'ii',
    __syscall_dup: function(fd) {
	/* Modified by Benoit Baudaux 22/1/2023 */
    /*var old = SYSCALLS.getStreamFromFD(fd);
      return FS.createStream(old, 0).fd;*/

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 20;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 19; // DUP

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // fd
	    buf2[12] = fd & 0xff;
	    buf2[13] = (fd >> 8) & 0xff;
	    buf2[14] = (fd >> 16) & 0xff;
	    buf2[15] = (fd >> 24) & 0xff;

	    // new_fd
	    buf2[16] = 0xff;
	    buf2[17] = 0xff;
	    buf2[18] = 0xff;
	    buf2[19] = 0xff;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (19|0x80)) {

		    //console.log(messageEvent);
		    
		    let new_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    Module['fd_table'][new_fd] = Module['fd_table'][fd];

		    wakeUp(new_fd);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	});

	return ret;
    },
    __syscall_dup2__sig: 'iii',
    __syscall_dup2: function(fd, new_fd) {
	/* Modified by Benoit Baudaux 22/1/2023 */
    /*var old = SYSCALLS.getStreamFromFD(fd);
      return FS.createStream(old, 0).fd;*/

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 20;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 19; // DUP

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // fd
	    buf2[12] = fd & 0xff;
	    buf2[13] = (fd >> 8) & 0xff;
	    buf2[14] = (fd >> 16) & 0xff;
	    buf2[15] = (fd >> 24) & 0xff;

	    // new_fd
	    buf2[16] = new_fd & 0xff;
	    buf2[17] = (new_fd >> 8) & 0xff;
	    buf2[18] = (new_fd >> 16) & 0xff;
	    buf2[19] = (new_fd >> 24) & 0xff;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (19|0x80)) {

		    //console.log(messageEvent);
		    
		    let new_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    Module['fd_table'][new_fd] = Module['fd_table'][fd];

		    wakeUp(new_fd);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	});

	return ret;
  },
  __syscall_pipe__deps: ['$PIPEFS'],
  __syscall_pipe__sig: 'ip',
  __syscall_pipe: function(fdPtr) {
    if (fdPtr == 0) {
      throw new FS.ErrnoError({{{ cDefine('EFAULT') }}});
    }

    var res = PIPEFS.createPipe();

    {{{ makeSetValue('fdPtr', 0, 'res.readable_fd', 'i32') }}};
    {{{ makeSetValue('fdPtr', 4, 'res.writable_fd', 'i32') }}};

    return 0;
  },
    __syscall_ioctl__sig: 'iiip',
    __syscall_ioctl: function(fd, op, varargs) {
	/*
#if SYSCALLS_REQUIRE_FILESYSTEM == 0
#if SYSCALL_DEBUG
    dbg('no-op in ioctl syscall due to SYSCALLS_REQUIRE_FILESYSTEM=0');
#endif
    return 0;
#else
    var stream = SYSCALLS.getStreamFromFD(fd);

    var ret = Asyncify.handleSleep(function(wakeUp) {

      stream.asynsify_wakeup = wakeUp;
      stream.asynsify_wakeup_consumed = false;

      function _ioctl() {

        switch (op) {
          case {{{ cDefine('TCGETA') }}}: {
            return 0;
          }
          case {{{ cDefine('TCGETS') }}}: {
            if (!stream.tty) return -{{{ cDefine('ENOTTY') }}};
    #if SYSCALL_DEBUG
            dbg('warning: not filling tio struct');
    #endif
            // Modified be Benoit Baudaux 9/11/2022
            //return 0;

            var argp = SYSCALLS.get();
            return FS.ioctl(stream, op, argp);
          }
          case {{{ cDefine('TCSETA') }}}:
          case {{{ cDefine('TCSETAW') }}}:
          case {{{ cDefine('TCSETAF') }}}: {
            if (!stream.tty) return -{{{ cDefine('ENOTTY') }}};

            return 0; // no-op, not actually adjusting terminal settings
          }
          case {{{ cDefine('TCSETS') }}}:
          case {{{ cDefine('TCSETSW') }}}:
          case {{{ cDefine('TCSETSF') }}}: {
            if (!stream.tty) return -{{{ cDefine('ENOTTY') }}};

            // Modified be Benoit Baudaux 9/11/2022
            //return 0; // no-op, not actually adjusting terminal settings

            var argp = SYSCALLS.get();
            return FS.ioctl(stream, op, argp);
          }
          case {{{ cDefine('TIOCGPGRP') }}}: {
            if (!stream.tty) return -{{{ cDefine('ENOTTY') }}};
            var argp = SYSCALLS.get();
            {{{ makeSetValue('argp', 0, 0, 'i32') }}};
            return 0;
          }
          case {{{ cDefine('TIOCSPGRP') }}}: {
            if (!stream.tty) return -{{{ cDefine('ENOTTY') }}};
            return -{{{ cDefine('EINVAL') }}}; // not supported
          }
          case {{{ cDefine('FIONREAD') }}}: {
            var argp = SYSCALLS.get();
            return FS.ioctl(stream, op, argp);
          }
          case {{{ cDefine('TIOCGWINSZ') }}}: {
            // TODO: in theory we should write to the winsize struct that gets
            // passed in, but for now musl doesn't read anything on it
            if (!stream.tty) return -{{{ cDefine('ENOTTY') }}};

            // Modified be Benoit Baudaux 10/11/2022
            //return 0;

            var argp = SYSCALLS.get();
            return FS.ioctl(stream, op, argp);
          }
          case {{{ cDefine('TIOCSWINSZ') }}}: {
            // TODO: technically, this ioctl call should change the window size.
            // but, since emscripten doesn't have any concept of a terminal window
            // yet, we'll just silently throw it away as we do TIOCGWINSZ
            if (!stream.tty) return -{{{ cDefine('ENOTTY') }}};
            return 0;
          }
          default: return -{{{ cDefine('EINVAL') }}}; // not supported
        }
      }

      var r = _ioctl();

      if (!stream.asynsify_wakeup_consumed)
        wakeUp(r);

      //return 0;
      });*/
	
	/* ops 21505 (TCGETS), 21506 (TCSETS), 21515 (TCFLSH), 21523 (TIOCGWINSZ) */

	//console.log("__syscall_ioctl: op=" +op);

	var argp = SYSCALLS.get();
	
	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_ioctl = () => {
	
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 14; // IOCTL

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;

		// remote_fd
		buf2[12] = remote_fd & 0xff;
		buf2[13] = (remote_fd >> 8) & 0xff;
		buf2[14] = (remote_fd >> 16) & 0xff;
		buf2[15] = (remote_fd >> 24) & 0xff;

		// op
		buf2[16] = op & 0xff;
		buf2[17] = (op >> 8) & 0xff;
		buf2[18] = (op >> 16) & 0xff;
		buf2[19] = (op >> 24) & 0xff;
		
		let len = 0;

		if ( (op == {{{ cDefine('TCSETS') }}}) || (op == {{{ cDefine('TCSETSW') }}}) || (op == {{{ cDefine('TCSETSF') }}}) ) {

		    len = 60; // 4*4+4+32+2*4;
		}
		else if (op == {{{ cDefine('TIOCSPGRP') }}}) {

		    len = 4;
		}

		buf2[20] = len & 0xff;
		buf2[21] = (len >> 8) & 0xff;
		buf2[22] = (len >> 16) & 0xff;
		buf2[23] = (len >> 24) & 0xff;

		if (len > 0) {

		    buf2.set(Module.HEAPU8.slice(argp, argp+len), 24);
		}

		if (op == {{{ cDefine('TIOCSCTTY') }}}) {

		    // argp is int
		    
		    buf2[24] = argp & 0xff;
		    buf2[25] = (argp >> 8) & 0xff;
		    buf2[26] = (argp >> 16) & 0xff;
		    buf2[27] = (argp >> 24) & 0xff;
		}

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (14|0x80)) {

			let op2 = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			if (op2 != op) {

			    return -1;
			}

			let errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			switch(op2) {

			case {{{ cDefine('TIOCGWINSZ') }}}:

			    if (!errno) {

				let len = 8;
				
				Module.HEAPU8.set(msg2.buf.slice(24, 24+len), argp);
				wakeUp(0);
			    }
			    else {

				wakeUp(-1);
			    }
			    
			    break;

			case {{{ cDefine('TCGETS') }}}:

			    if (!errno) {

				let len = 60; // 4*4+4+32+2*4;
				
				Module.HEAPU8.set(msg2.buf.slice(24, 24+len), argp);
				wakeUp(0);
			    }
			    else {

				wakeUp(-1);
			    }
			    
			    break;

			case {{{ cDefine('TIOCGPGRP') }}}:

			    if (!errno) {

				let len = 4;
				
				Module.HEAPU8.set(msg2.buf.slice(24, 24+len), argp);				
				wakeUp(0);
			    }
			    else {

				wakeUp(-1);
			    }
			    
			    break;

			default:

			    wakeUp(0);
			    
			    break;
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {

		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
		driver_bc.postMessage(msg);
	    }

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_ioctl();
	    }
	    else {
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;

			    do_ioctl();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }

	    
	});

    return ret;

#endif // SYSCALLS_REQUIRE_FILESYSTEM
  },
  __syscall_symlink__sig: 'ipp',
  __syscall_symlink: function(target, linkpath) {
    target = SYSCALLS.getStr(target);
    linkpath = SYSCALLS.getStr(linkpath);
    FS.symlink(target, linkpath);
    return 0;
  },
  __syscall_fchmod: function(fd, mode) {
    FS.fchmod(fd, mode);
    return 0;
  },
// When building with PROXY_POSIX_SOCKETS the socket syscalls are implemented
// natively in libsockets.a.
// When building with WASMFS the socket syscalls are implemented natively in
// libwasmfs.a.
#if PROXY_POSIX_SOCKETS == 0 && WASMFS == 0
  $getSocketFromFD__deps: ['$SOCKFS', '$FS'],
  $getSocketFromFD: function(fd) {
    var socket = SOCKFS.getSocket(fd);
    if (!socket) throw new FS.ErrnoError({{{ cDefine('EBADF') }}});
#if SYSCALL_DEBUG
    dbg('    (socket: "' + socket.path + '")');
#endif
    return socket;
  },
  /** @param {boolean=} allowNull */
  $getSocketAddress__deps: ['$readSockaddr', '$FS', '$DNS'],
  $getSocketAddress__docs: '/** @param {boolean=} allowNull */',
  $getSocketAddress: function(addrp, addrlen, allowNull) {
    if (allowNull && addrp === 0) return null;
      var info = readSockaddr(addrp, addrlen);
      if (info.errno) throw new FS.ErrnoError(info.errno);
      /* Modified by Benoit Baudaux 26/12/2022 */
      if (info.family != {{{ cDefine('AF_UNIX') }}} )
	  info.addr = DNS.lookup_addr(info.addr) || info.addr;
#if SYSCALL_DEBUG
    dbg('    (socketaddress: "' + [info.addr, info.port] + '")');
#endif
    return info;
  },
    /* Modified by Benoit Baudaux 26/12/2022 */
    __syscall_socket__deps: ['$SOCKFS'],
    __syscall_socket: function(domain, type, protocol) {

	//var sock = SOCKFS.createSocket(domain, type, protocol);
#if ASSERTIONS
    //assert(sock.stream.fd < 64); // XXX ? select() assumes socket fd values are in 0..63
#endif
	//return sock.stream.fd;

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    if (window.frameElement.getAttribute('pid') != "1") {

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		let buf = new Uint8Array(256);

		buf[0] = 9; // SOCKET
		
		/*//padding
		  buf[1] = 0;
		  buf[2] = 0;
		  buf[3] = 0;*/

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf[4] = pid & 0xff;
		buf[5] = (pid >> 8) & 0xff;
		buf[6] = (pid >> 16) & 0xff;
		buf[7] = (pid >> 24) & 0xff;

		// errno
		buf[8] = 0x0;
		buf[9] = 0x0;
		buf[10] = 0x0;
		buf[11] = 0x0;

		// fd
		buf[12] = 0x0;
		buf[3] = 0x0;
		buf[14] = 0x0;
		buf[15] = 0x0;
		
		// domain
		buf[16] = domain & 0xff;
		buf[17] = (domain >> 8) & 0xff;
		buf[18] = (domain >> 16) & 0xff;
		buf[19] = (domain >> 24) & 0xff;

		// type
		buf[20] = type & 0xff;
		buf[21] = (type >> 8) & 0xff;
		buf[22] = (type >> 16) & 0xff;
		buf[23] = (type >> 24) & 0xff;

		// protocol
		buf[24] = protocol & 0xff;
		buf[25] = (protocol >> 8) & 0xff;
		buf[26] = (protocol >> 16) & 0xff;
		buf[27] = (protocol >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (9|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (_errno == 0) {

			    let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			    // create our internal socket structure
			    var sock = {
				fd: fd,
				family: domain,
				type: type,
				protocol: protocol,
				server: null,
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
#if SOCKET_WEBRTC
#else
				//sock_ops: SOCKFS.websocket_sock_ops
				// TODO: all types of socket
				sock_ops: SOCKFS.unix_dgram_sock_ops,
#endif
			    };

			    Module['fd_table'][fd] = sock;

			    wakeUp(fd);
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }

		    return -1;
		});

		let msg = {

		    from: Module['rcv_bc_channel'].name,
		    buf: buf,
		    len: 256
		};

		bc.postMessage(msg);
	    }
	    else {

		if (!Module['fd_table']) {

		    Module['fd_table'] = {};
		    Module['fd_table'].last_fd = 0;
		}

		Module['fd_table'].last_fd += 1;

		// create our internal socket structure
		var sock = {
		    fd: Module['fd_table'].last_fd,
		    family: domain,
		    type: type,
		    protocol: protocol,
		    server: null,
		    error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
		    peers: {},
		    pending: [],
		    recv_queue: [],
		    name: null,
		    bc: null,
#if SOCKET_WEBRTC
#else
		    //sock_ops: SOCKFS.websocket_sock_ops
		    // TODO: all types of socket
		    sock_ops: SOCKFS.unix_dgram_sock_ops,
#endif
		};

		Module['fd_table'][Module['fd_table'].last_fd] = sock;

		wakeUp(Module['fd_table'].last_fd);
	    }
	});

	return ret;
  },
  __syscall_getsockname__deps: ['$getSocketFromFD', '$writeSockaddr', '$DNS'],
  __syscall_getsockname: function(fd, addr, addrlen) {
    err("__syscall_getsockname " + fd);
    var sock = getSocketFromFD(fd);
    // TODO: sock.saddr should never be undefined, see TODO in websocket_sock_ops.getname
    var errno = writeSockaddr(addr, sock.family, DNS.lookup_name(sock.saddr || '0.0.0.0'), sock.sport, addrlen);
#if ASSERTIONS
    assert(!errno);
#endif
    return 0;
  },
  __syscall_getpeername__deps: ['$getSocketFromFD', '$writeSockaddr', '$DNS'],
  __syscall_getpeername: function(fd, addr, addrlen) {
    var sock = getSocketFromFD(fd);
    if (!sock.daddr) {
      return -{{{ cDefine('ENOTCONN') }}}; // The socket is not connected.
    }
    var errno = writeSockaddr(addr, sock.family, DNS.lookup_name(sock.daddr), sock.dport, addrlen);
#if ASSERTIONS
    assert(!errno);
#endif
    return 0;
  },
  __syscall_connect__deps: ['$getSocketFromFD', '$getSocketAddress'],
  __syscall_connect__sig: 'iipi',
  __syscall_connect: function(fd, addr, addrlen) {
    var sock = getSocketFromFD(fd);
    var info = getSocketAddress(addr, addrlen);
    sock.sock_ops.connect(sock, info.addr, info.port);
    return 0;
  },
  __syscall_shutdown__deps: ['$getSocketFromFD'],
  __syscall_shutdown: function(fd, how) {
    getSocketFromFD(fd);
    return -{{{ cDefine('ENOSYS') }}}; // unsupported feature
  },
  __syscall_accept4__deps: ['$getSocketFromFD', '$writeSockaddr', '$DNS'],
  __syscall_accept4: function(fd, addr, addrlen, flags) {
    var sock = getSocketFromFD(fd);
    var newsock = sock.sock_ops.accept(sock);
    if (addr) {
      var errno = writeSockaddr(addr, newsock.family, DNS.lookup_name(newsock.daddr), newsock.dport, addrlen);
#if ASSERTIONS
      assert(!errno);
#endif
    }
    return newsock.stream.fd;
  },
  __syscall_bind__deps: ['$getSocketFromFD', '$getSocketAddress'],
  __syscall_bind__sig: 'iipi',
    __syscall_bind: function(fd, addr, addrlen) {

	var sock = getSocketFromFD(fd);
	var info = getSocketAddress(addr, addrlen);

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    sock.wakeUp = wakeUp;

	    /* Modified by Benoit Baudaux 26/12/2022 */
	    sock.sock_ops.bind(sock, info.addr, info.port);
	    /*return 0;*/
	});
	
	return ret;
  },
  __syscall_listen__deps: ['$getSocketFromFD'],
  __syscall_listen: function(fd, backlog) {
    var sock = getSocketFromFD(fd);
    sock.sock_ops.listen(sock, backlog);
    return 0;
  },
  __syscall_recvfrom__deps: ['$getSocketFromFD', '$writeSockaddr', '$DNS'],
    __syscall_recvfrom: function(fd, buf, len, flags, addr, addrlen) {
	/* Modified by Benoit Baudaux 26/12/2022 */
    var sock = getSocketFromFD(fd);
    /*var msg = sock.sock_ops.recvmsg(sock, len);
    if (!msg) return 0; // socket is closed
    if (addr) {
      var errno = writeSockaddr(addr, sock.family, DNS.lookup_name(msg.addr), msg.port, addrlen);
#if ASSERTIONS
      assert(!errno);
#endif
    }
    HEAPU8.set(msg.buffer, buf);

    return msg.buffer.byteLength;*/

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    sock.wakeUp = wakeUp;

	    sock.sock_ops.recvfrom(sock, buf, len, flags, addr, addrlen);
	});
	
	return ret;
  },
  __syscall_sendto__deps: ['$getSocketFromFD', '$getSocketAddress'],
  __syscall_sendto__sig: 'iipiipi',
    __syscall_sendto: function(fd, message, length, flags, addr, addr_len) {

	var sock = getSocketFromFD(fd);
	
      var dest = getSocketAddress(addr, addr_len, true);
      /* Modified by Benoit Baudaux 26/12/2022 */
    /*if (!dest) {
      // send, no address provided
      return FS.write(sock.stream, {{{ heapAndOffset('HEAP8', 'message') }}}, length);
    }
    // sendto an address
    return sock.sock_ops.sendmsg(sock, {{{ heapAndOffset('HEAP8', 'message') }}}, length, dest.addr, dest.port);*/

      let uint8 = Module.HEAPU8.slice(message,message+length);
      
      return sock.sock_ops.sendto(sock, uint8, length, flags, dest.addr, dest.port);
  },
  __syscall_getsockopt__deps: ['$getSocketFromFD'],
  __syscall_getsockopt: function(fd, level, optname, optval, optlen) {
    var sock = getSocketFromFD(fd);
    // Minimal getsockopt aimed at resolving https://github.com/emscripten-core/emscripten/issues/2211
    // so only supports SOL_SOCKET with SO_ERROR.
    if (level === {{{ cDefine('SOL_SOCKET') }}}) {
      if (optname === {{{ cDefine('SO_ERROR') }}}) {
        {{{ makeSetValue('optval', 0, 'sock.error', 'i32') }}};
        {{{ makeSetValue('optlen', 0, 4, 'i32') }}};
        sock.error = null; // Clear the error (The SO_ERROR option obtains and then clears this field).
        return 0;
      }
    }
    return -{{{ cDefine('ENOPROTOOPT') }}}; // The option is unknown at the level indicated.
  },
  __syscall_sendmsg__deps: ['$getSocketFromFD', '$readSockaddr', '$DNS'],
  __syscall_sendmsg: function(fd, message, flags) {
    var sock = getSocketFromFD(fd);
    var iov = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iov, '*') }}};
    var num = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iovlen, 'i32') }}};
    // read the address and port to send to
    var addr, port;
    var name = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_name, '*') }}};
    var namelen = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_namelen, 'i32') }}};
    if (name) {
      var info = readSockaddr(name, namelen);
      if (info.errno) return -info.errno;
      port = info.port;
      addr = DNS.lookup_addr(info.addr) || info.addr;
    }
    // concatenate scatter-gather arrays into one message buffer
    var total = 0;
    for (var i = 0; i < num; i++) {
      total += {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
    }
    var view = new Uint8Array(total);
    var offset = 0;
    for (var i = 0; i < num; i++) {
      var iovbase = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_base, POINTER_TYPE) }}};
      var iovlen = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
      for (var j = 0; j < iovlen; j++) {  
        view[offset++] = {{{ makeGetValue('iovbase', 'j', 'i8') }}};
      }
    }
    // write the buffer
    return sock.sock_ops.sendmsg(sock, view, 0, total, addr, port);
  },
  __syscall_recvmsg__deps: ['$getSocketFromFD', '$writeSockaddr', '$DNS'],
  __syscall_recvmsg: function(fd, message, flags) {
    var sock = getSocketFromFD(fd);
    var iov = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iov, POINTER_TYPE) }}};
    var num = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iovlen, 'i32') }}};
    // get the total amount of data we can read across all arrays
    var total = 0;
    for (var i = 0; i < num; i++) {
      total += {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
    }
    // try to read total data
    var msg = sock.sock_ops.recvmsg(sock, total);
    if (!msg) return 0; // socket is closed

    // TODO honor flags:
    // MSG_OOB
    // Requests out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
    // MSG_PEEK
    // Peeks at the incoming message.
    // MSG_WAITALL
    // Requests that the function block until the full amount of data requested can be returned. The function may return a smaller amount of data if a signal is caught, if the connection is terminated, if MSG_PEEK was specified, or if an error is pending for the socket.

    // write the source address out
    var name = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_name, '*') }}};
    if (name) {
      var errno = writeSockaddr(name, sock.family, DNS.lookup_name(msg.addr), msg.port);
#if ASSERTIONS
      assert(!errno);
#endif
    }
    // write the buffer out to the scatter-gather arrays
    var bytesRead = 0;
    var bytesRemaining = msg.buffer.byteLength;
    for (var i = 0; bytesRemaining > 0 && i < num; i++) {
      var iovbase = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_base, POINTER_TYPE) }}};
      var iovlen = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
      if (!iovlen) {
        continue;
      }
      var length = Math.min(iovlen, bytesRemaining);
      var buf = msg.buffer.subarray(bytesRead, bytesRead + length);
      HEAPU8.set(buf, iovbase + bytesRead);
      bytesRead += length;
      bytesRemaining -= length;
    }

    // TODO set msghdr.msg_flags
    // MSG_EOR
    // End of record was received (if supported by the protocol).
    // MSG_OOB
    // Out-of-band data was received.
    // MSG_TRUNC
    // Normal data was truncated.
    // MSG_CTRUNC

    return bytesRead;
  },
#endif // ~PROXY_POSIX_SOCKETS==0
  __syscall_fchdir: function(fd) {
    var stream = SYSCALLS.getStreamFromFD(fd);
    FS.chdir(stream.path);
    return 0;
  },
  __syscall__newselect: function(nfds, readfds, writefds, exceptfds, timeout) {
    // readfds are supported,
    // writefds checks socket open status
    // exceptfds not supported
    // timeout is always 0 - fully async
#if ASSERTIONS
    assert(nfds <= 64, 'nfds must be less than or equal to 64');  // fd sets have 64 bits // TODO: this could be 1024 based on current musl headers
    assert(!exceptfds, 'exceptfds not supported');
#endif

    var total = 0;
    
    var srcReadLow = (readfds ? {{{ makeGetValue('readfds', 0, 'i32') }}} : 0),
        srcReadHigh = (readfds ? {{{ makeGetValue('readfds', 4, 'i32') }}} : 0);
    var srcWriteLow = (writefds ? {{{ makeGetValue('writefds', 0, 'i32') }}} : 0),
        srcWriteHigh = (writefds ? {{{ makeGetValue('writefds', 4, 'i32') }}} : 0);
    var srcExceptLow = (exceptfds ? {{{ makeGetValue('exceptfds', 0, 'i32') }}} : 0),
        srcExceptHigh = (exceptfds ? {{{ makeGetValue('exceptfds', 4, 'i32') }}} : 0);

    var dstReadLow = 0,
        dstReadHigh = 0;
    var dstWriteLow = 0,
        dstWriteHigh = 0;
    var dstExceptLow = 0,
        dstExceptHigh = 0;

    var allLow = (readfds ? {{{ makeGetValue('readfds', 0, 'i32') }}} : 0) |
                 (writefds ? {{{ makeGetValue('writefds', 0, 'i32') }}} : 0) |
                 (exceptfds ? {{{ makeGetValue('exceptfds', 0, 'i32') }}} : 0);
    var allHigh = (readfds ? {{{ makeGetValue('readfds', 4, 'i32') }}} : 0) |
                  (writefds ? {{{ makeGetValue('writefds', 4, 'i32') }}} : 0) |
                  (exceptfds ? {{{ makeGetValue('exceptfds', 4, 'i32') }}} : 0);

    var check = function(fd, low, high, val) {
      return (fd < 32 ? (low & val) : (high & val));
    };

    for (var fd = 0; fd < nfds; fd++) {
      var mask = 1 << (fd % 32);
      if (!(check(fd, allLow, allHigh, mask))) {
        continue;  // index isn't in the set
      }

      var stream = SYSCALLS.getStreamFromFD(fd);

      var flags = SYSCALLS.DEFAULT_POLLMASK;

      if (stream.stream_ops.poll) {
        flags = stream.stream_ops.poll(stream);
      }

      if ((flags & {{{ cDefine('POLLIN') }}}) && check(fd, srcReadLow, srcReadHigh, mask)) {
        fd < 32 ? (dstReadLow = dstReadLow | mask) : (dstReadHigh = dstReadHigh | mask);
        total++;
      }
      if ((flags & {{{ cDefine('POLLOUT') }}}) && check(fd, srcWriteLow, srcWriteHigh, mask)) {
        fd < 32 ? (dstWriteLow = dstWriteLow | mask) : (dstWriteHigh = dstWriteHigh | mask);
        total++;
      }
      if ((flags & {{{ cDefine('POLLPRI') }}}) && check(fd, srcExceptLow, srcExceptHigh, mask)) {
        fd < 32 ? (dstExceptLow = dstExceptLow | mask) : (dstExceptHigh = dstExceptHigh | mask);
        total++;
      }
    }

    if (readfds) {
      {{{ makeSetValue('readfds', '0', 'dstReadLow', 'i32') }}};
      {{{ makeSetValue('readfds', '4', 'dstReadHigh', 'i32') }}};
    }
    if (writefds) {
      {{{ makeSetValue('writefds', '0', 'dstWriteLow', 'i32') }}};
      {{{ makeSetValue('writefds', '4', 'dstWriteHigh', 'i32') }}};
    }
    if (exceptfds) {
      {{{ makeSetValue('exceptfds', '0', 'dstExceptLow', 'i32') }}};
      {{{ makeSetValue('exceptfds', '4', 'dstExceptHigh', 'i32') }}};
    }

    return total;
  },
  _msync_js__sig: 'ippiiip',
  _msync_js: function(addr, len, prot, flags, fd, offset) {
    SYSCALLS.doMsync(addr, SYSCALLS.getStreamFromFD(fd), len, flags, 0);
    return 0;
  },
  __syscall_fdatasync: function(fd) {
    var stream = SYSCALLS.getStreamFromFD(fd);
    return 0; // we can't do anything synchronously; the in-memory FS is already synced to
  },
  __syscall_poll__sig: 'ipii',
  __syscall_poll: function(fds, nfds, timeout) {
    var nonzero = 0;
    for (var i = 0; i < nfds; i++) {
      var pollfd = fds + {{{ C_STRUCTS.pollfd.__size__ }}} * i;
      var fd = {{{ makeGetValue('pollfd', C_STRUCTS.pollfd.fd, 'i32') }}};
      var events = {{{ makeGetValue('pollfd', C_STRUCTS.pollfd.events, 'i16') }}};
      var mask = {{{ cDefine('POLLNVAL') }}};
      var stream = FS.getStream(fd);
      if (stream) {
        mask = SYSCALLS.DEFAULT_POLLMASK;
        if (stream.stream_ops.poll) {
          mask = stream.stream_ops.poll(stream);
        }
      }
      mask &= events | {{{ cDefine('POLLERR') }}} | {{{ cDefine('POLLHUP') }}};
      if (mask) nonzero++;
      {{{ makeSetValue('pollfd', C_STRUCTS.pollfd.revents, 'mask', 'i16') }}};
    }
    return nonzero;
  },
  __syscall_getcwd__sig: 'ipp',
    __syscall_getcwd: function(buf, size) {

	/* Modified by Benoit Baudaux 19/03/2023 */

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 256;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 34; // GETCWD

	    /*//padding
	      buf[1] = 0;
	      buf[2] = 0;
	      buf[3] = 0;*/

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);
		
		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (34|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_stat64: _errno="+_errno);

		    if (_errno == 0) {

			let len = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			if (buf) {

			    if (len <=  size) {

				//console.log("__syscall_stat64: len="+len);

				Module.HEAPU8.set(msg2.buf.slice(16, 16+len), buf);
				wakeUp(len);
			    }
			    else {

				wakeUp( -{{{ cDefine('ERANGE') }}} );
			    }
			}
			else {
			    
			    //TODO: alloc buf
			}
		    }
		    else {

			wakeUp(-1);
		    }

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");
	    
	    bc.postMessage(msg);

	});

	return ret;

      /*if (size === 0) return -{{{ cDefine('EINVAL') }}};
	var cwd = FS.cwd();
    var cwdLengthInBytes = lengthBytesUTF8(cwd) + 1;
    if (size < cwdLengthInBytes) return -{{{ cDefine('ERANGE') }}};
    stringToUTF8(cwd, buf, size);
    return cwdLengthInBytes;*/

  },
  __syscall_truncate64__sig: 'ipj',
  __syscall_truncate64__deps: i53ConversionDeps,
  __syscall_truncate64: function(path, {{{ defineI64Param('length') }}}) {
    {{{ receiveI64ParamAsI53('length', -cDefine('EOVERFLOW')) }}}
    path = SYSCALLS.getStr(path);
    FS.truncate(path, length);
    return 0;
  },
  __syscall_ftruncate64__sig: 'iij',
  __syscall_ftruncate64__deps: i53ConversionDeps,
  __syscall_ftruncate64: function(fd, {{{ defineI64Param('length') }}}) {
    {{{ receiveI64ParamAsI53('length', -cDefine('EOVERFLOW')) }}}
    FS.ftruncate(fd, length);
    return 0;
  },
  __syscall_stat64__sig: 'ipp',
    __syscall_stat64: function(path, buf) {

	//console.log("__syscall_stat64: "+SYSCALLS.getStr(path));

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 1256;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 28; // STAT

	    /*//padding
	      buf[1] = 0;
	      buf[2] = 0;
	      buf[3] = 0;*/

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    // errno
	    buf2[8] = 0x0;
	    buf2[9] = 0x0;
	    buf2[10] = 0x0;
	    buf2[11] = 0x0;

	    let path_len = 0;

	    while (Module.HEAPU8[path+path_len]) {

		path_len++;
	    }

	    path_len++;

	    buf2[12] = path_len & 0xff;
	    buf2[13] = (path_len >> 8) & 0xff;
	    buf2[14] = (path_len >> 16) & 0xff;
	    buf2[15] = (path_len >> 24) & 0xff;

	    buf2.set(Module.HEAPU8.slice(path, path+path_len), 16);
	    
	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);
		
		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (28|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_stat64: _errno="+_errno);

		    if (_errno == 0) {

			let len = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			//console.log("__syscall_stat64: len="+len);

			Module.HEAPU8.set(msg2.buf.slice(16, 16+len), buf);

			wakeUp(0);
		    }
		    else {

			wakeUp(-1);
		    }

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");
	    
	    bc.postMessage(msg);

	});

	return ret;
	
	/* Modified by Benoit Baudaux 8/2/2023 */
    /*path = SYSCALLS.getStr(path);
    return SYSCALLS.doStat(FS.stat, path, buf);*/
  },
  __syscall_lstat64__sig: 'ipp',
    __syscall_lstat64: function(path, buf) {

	//console.log("__syscall_lstat64: "+SYSCALLS.getStr(path));

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 1256;
	
	    let buf2 = new Uint8Array(buf_size);
	    
	    buf2[0] = 30; // LSTAT

	    /*//padding
	      buf[1] = 0;
	      buf[2] = 0;
	      buf[3] = 0;*/

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // errno
	    buf2[8] = 0x0;
	    buf2[9] = 0x0;
	    buf2[10] = 0x0;
	    buf2[11] = 0x0;

	    let path_len = 0;

	    while (Module.HEAPU8[path+path_len]) {

		path_len++;
	    }

	    path_len++;

	    buf2[12] = path_len & 0xff;
	    buf2[13] = (path_len >> 8) & 0xff;
	    buf2[14] = (path_len >> 16) & 0xff;
	    buf2[15] = (path_len >> 24) & 0xff;

	    buf2.set(Module.HEAPU8.slice(path,path+path_len), 16);
	    
	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);
		
		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (30|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_lstat64: _errno="+_errno);

		    if (_errno == 0) {

			let len = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			//console.log("__syscall_lstat64: len="+len);

			Module.HEAPU8.set(msg2.buf.slice(16, 16+len), buf);

			wakeUp(0);
		    }
		    else {

			wakeUp(-1);
		    }

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");
	    
	    bc.postMessage(msg);

	});

	return ret;

	/* Modified by Benoit Baudaux 8/2/2023 */
    /*path = SYSCALLS.getStr(path);
    return SYSCALLS.doStat(FS.lstat, path, buf);*/
  },
    __syscall_fstat64__sig: 'iip',
    __syscall_fstat64: function(fd, buf) {

	//console.log("__syscall_fstat64: fd="+fd);

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_fstat = () => {
		
		let buf_size = 1256;
		
		let buf2 = new Uint8Array(buf_size);
		
		buf2[0] = 29; // FSTAT
		
		let pid = parseInt(window.frameElement.getAttribute('pid'));
		
		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;
	       
		// remote_fd
		buf2[12] = remote_fd & 0xff;
		buf2[13] = (remote_fd >> 8) & 0xff;
		buf2[14] = (remote_fd >> 16) & 0xff;
		buf2[15] = (remote_fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (29|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);
			
			if (_errno == 0) {

			    let len = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			    //console.log("__syscall_fstat64: len="+len);

			    Module.HEAPU8.set(msg2.buf.slice(20, 20+len), buf);

			    wakeUp(0);
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
		driver_bc.postMessage(msg);
	    };

	   if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_fstat();
	    }
	    else {
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;
			    
			    do_fstat();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }
	});
    
    return ret;

	/* Modified by Benoit Baudaux 8/2/2023 */
    /*var stream = SYSCALLS.getStreamFromFD(fd);
    return SYSCALLS.doStat(FS.stat, stream.path, buf);*/
  },
  __syscall_fchown32: function(fd, owner, group) {
    FS.fchown(fd, owner, group);
    return 0;
  },
  __syscall_getdents64__sig: 'iipi',
    __syscall_getdents64: function(fd, dirp, count) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 256;
	
	    let buf2 = new Uint8Array(buf_size);
	    
	    buf2[0] = 36; // GETDENTS

	    /*//padding
	      buf[1] = 0;
	      buf[2] = 0;
	      buf[3] = 0;*/

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // errno
	    buf2[8] = 0x0;
	    buf2[9] = 0x0;
	    buf2[10] = 0x0;
	    buf2[11] = 0x0;

	    let remote_fd = Module['fd_table'][fd].remote_fd;
	       
	    // remote_fd
	    buf2[12] = remote_fd & 0xff;
	    buf2[13] = (remote_fd >> 8) & 0xff;
	    buf2[14] = (remote_fd >> 16) & 0xff;
	    buf2[15] = (remote_fd >> 24) & 0xff;

	    // count
	    buf2[16] = count & 0xff;
	    buf2[17] = (count >> 8) & 0xff;
	    buf2[18] = (count >> 16) & 0xff;
	    buf2[19] = (count >> 24) & 0xff;
	    
	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);
		
		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (36|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_lstat64: _errno="+_errno);

		    if (_errno == 0) {

			let len = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			//console.log("__syscall_lstat64: len="+len);

			Module.HEAPU8.set(msg2.buf.slice(20, 20+len), dirp);

			wakeUp(len);
		    }
		    else {

			wakeUp(-1);
		    }

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
	    driver_bc.postMessage(msg);

	});

	return ret;
	
    /*var stream = SYSCALLS.getStreamFromFD(fd)
    if (!stream.getdents) {
      stream.getdents = FS.readdir(stream.path);
    }

    var struct_size = {{{ C_STRUCTS.dirent.__size__ }}};
    var pos = 0;
    var off = FS.llseek(stream, 0, {{{ cDefine('SEEK_CUR') }}});

    var idx = Math.floor(off / struct_size);

    while (idx < stream.getdents.length && pos + struct_size <= count) {
      var id;
      var type;
      var name = stream.getdents[idx];
      if (name === '.') {
        id = stream.node.id;
        type = 4; // DT_DIR
      }
      else if (name === '..') {
        var lookup = FS.lookupPath(stream.path, { parent: true });
        id = lookup.node.id;
        type = 4; // DT_DIR
      }
      else {
        var child = FS.lookupNode(stream.node, name);
        id = child.id;
        type = FS.isChrdev(child.mode) ? 2 :  // DT_CHR, character device.
               FS.isDir(child.mode) ? 4 :     // DT_DIR, directory.
               FS.isLink(child.mode) ? 10 :   // DT_LNK, symbolic link.
               8;                             // DT_REG, regular file.
      }
#if ASSERTIONS
      assert(id);
#endif
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_ino, 'id', 'i64') }}};
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_off, '(idx + 1) * struct_size', 'i64') }}};
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_reclen, C_STRUCTS.dirent.__size__, 'i16') }}};
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_type, 'type', 'i8') }}};
      stringToUTF8(name, dirp + pos + {{{ C_STRUCTS.dirent.d_name }}}, 256);
      pos += struct_size;
      idx += 1;
    }
    FS.llseek(stream, idx * struct_size, {{{ cDefine('SEEK_SET') }}});
    return pos;*/
  },
  __syscall_fcntl64__deps: ['$setErrNo'],
  __syscall_fcntl64__sig: 'iiip',
  __syscall_fcntl64: function(fd, cmd, varargs) {
#if SYSCALLS_REQUIRE_FILESYSTEM == 0
#if SYSCALL_DEBUG
    dbg('no-op in fcntl syscall due to SYSCALLS_REQUIRE_FILESYSTEM=0');
#endif
    return 0;
#else

      //console.log("__syscall_fcntl: cmd="+cmd);

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  let do_fcntl = () => {
	
	    let buf_size = 256;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 17; // FCNTL

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	      //console.log(Module['fd_table'][fd]);

	    let remote_fd = (fd >= 0)? Module['fd_table'][fd].remote_fd : -1;

	    // remote_fd
	    buf2[12] = remote_fd & 0xff;
	    buf2[13] = (remote_fd >> 8) & 0xff;
	    buf2[14] = (remote_fd >> 16) & 0xff;
	    buf2[15] = (remote_fd >> 24) & 0xff;

	    //cmd
	    buf2[16] = cmd & 0xff;
	    buf2[17] = (cmd >> 8) & 0xff;
	    buf2[18] = (cmd >> 16) & 0xff;
	    buf2[19] = (cmd >> 24) & 0xff;
	    

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (17|0x80)) {
		
		    wakeUp(0); // TODO: size

		    return 0;
		}
		else {

		    return -1;
		}
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
	    
	    driver_bc.postMessage(msg);
	};

	  if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

	      //console.log("__syscall_fcntl: "+fd+" found in fd_table");

		do_fcntl();
	    }
	  else {

	      //console.log("__syscall_fcntl: "+fd+" not found in fd_table");
	      
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;

			    do_fcntl();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }
	});
    
    return ret;

      /* Modified by Benoit Baudaux 17/1/2023 */
      /* Following code is not executed */
    var stream = SYSCALLS.getStreamFromFD(fd);
    switch (cmd) {
      case {{{ cDefine('F_DUPFD') }}}: {
        var arg = SYSCALLS.get();
        if (arg < 0) {
          return -{{{ cDefine('EINVAL') }}};
        }
        var newStream;
        newStream = FS.createStream(stream, arg);
        return newStream.fd;
      }
      case {{{ cDefine('F_GETFD') }}}:
      case {{{ cDefine('F_SETFD') }}}:
        return 0;  // FD_CLOEXEC makes no sense for a single process.
      case {{{ cDefine('F_GETFL') }}}:
        return stream.flags;
      case {{{ cDefine('F_SETFL') }}}: {
        var arg = SYSCALLS.get();
        stream.flags |= arg;
        return 0;
      }
      case {{{ cDefine('F_GETLK') }}}:
      /* case {{{ cDefine('F_GETLK64') }}}: Currently in musl F_GETLK64 has same value as F_GETLK, so omitted to avoid duplicate case blocks. If that changes, uncomment this */ {
        {{{ assert(cDefine('F_GETLK') === cDefine('F_GETLK64')), '' }}}
        var arg = SYSCALLS.get();
        var offset = {{{ C_STRUCTS.flock.l_type }}};
        // We're always unlocked.
        {{{ makeSetValue('arg', 'offset', cDefine('F_UNLCK'), 'i16') }}};
        return 0;
      }
      case {{{ cDefine('F_SETLK') }}}:
      case {{{ cDefine('F_SETLKW') }}}:
      /* case {{{ cDefine('F_SETLK64') }}}: Currently in musl F_SETLK64 has same value as F_SETLK, so omitted to avoid duplicate case blocks. If that changes, uncomment this */
      /* case {{{ cDefine('F_SETLKW64') }}}: Currently in musl F_SETLKW64 has same value as F_SETLKW, so omitted to avoid duplicate case blocks. If that changes, uncomment this */
        {{{ assert(cDefine('F_SETLK64') === cDefine('F_SETLK')), '' }}}
        {{{ assert(cDefine('F_SETLKW64') === cDefine('F_SETLKW')), '' }}}
        return 0; // Pretend that the locking is successful.
      case {{{ cDefine('F_GETOWN_EX') }}}:
      case {{{ cDefine('F_SETOWN') }}}:
        return -{{{ cDefine('EINVAL') }}}; // These are for sockets. We don't have them fully implemented yet.
      case {{{ cDefine('F_GETOWN') }}}:
        // musl trusts getown return values, due to a bug where they must be, as they overlap with errors. just return -1 here, so fcntl() returns that, and we set errno ourselves.
        setErrNo({{{ cDefine('EINVAL') }}});
        return -1;
      default: {
#if SYSCALL_DEBUG
        dbg('warning: fcntl unrecognized command ' + cmd);
#endif
        return -{{{ cDefine('EINVAL') }}};
      }
    }
#endif // SYSCALLS_REQUIRE_FILESYSTEM
  },

  __syscall_statfs64__sig: 'ippp',
  __syscall_statfs64: function(path, size, buf) {
    path = SYSCALLS.getStr(path);
#if ASSERTIONS
    assert(size === {{{ C_STRUCTS.statfs.__size__ }}});
#endif
    // NOTE: None of the constants here are true. We're just returning safe and
    //       sane values.
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_bsize, '4096', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_frsize, '4096', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_blocks, '1000000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_bfree, '500000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_bavail, '500000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_files, 'FS.nextInode', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_ffree, '1000000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_fsid, '42', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_flags, '2', 'i32') }}};  // ST_NOSUID
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_namelen, '255', 'i32') }}};
    return 0;
  },
  __syscall_fstatfs64__deps: ['__syscall_statfs64'],
  __syscall_fstatfs64: function(fd, size, buf) {
    var stream = SYSCALLS.getStreamFromFD(fd);
    return ___syscall_statfs64(0, size, buf);
  },
  __syscall_fadvise64__nothrow: true,
  __syscall_fadvise64__proxy: false,
  __syscall_fadvise64: function(fd, offset, len, advice) {
    return 0; // your advice is important to us (but we can't use it)
  },
    __syscall_openat__sig: 'iipip',
    __syscall_openat: function(dirfd, path, flags, varargs) {

	/* Modified by Benoit Baudaux 4/1/2023 */

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    if (window.frameElement.getAttribute('pid') != "1") {

		var mode = varargs ? SYSCALLS.get() : 0;

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		let buf_size = 1256;
	
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 11; // OPEN

		/*//padding
		  buf[1] = 0;
		  buf[2] = 0;
		  buf[3] = 0;*/

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// errno
		buf2[8] = 0x0;
		buf2[9] = 0x0;
		buf2[10] = 0x0;
		buf2[11] = 0x0;

		// fd
		buf2[12] = 0x0;
		buf2[13] = 0x0;
		buf2[14] = 0x0;
		buf2[15] = 0x0;

		// remote fd

		buf2[16] = 0x0;
		buf2[17] = 0x0;
		buf2[18] = 0x0;
		buf2[19] = 0x0;

		// flags
		buf2[20] = flags & 0xff;
		buf2[21] = (flags >> 8) & 0xff;
		buf2[22] = (flags >> 16) & 0xff;
		buf2[23] = (flags >> 24) & 0xff;
		
		// mode
		buf2[24] = mode & 0xff;
		buf2[25] = (mode >> 8) & 0xff;

		// pathname
		let path_len = 0;

		while (Module.HEAPU8[path+path_len]) {

		    path_len++;
		}

		path_len++;

		buf2.set(Module.HEAPU8.slice(path,path+path_len), 140);
		
		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);
		    
		    //console.log(messageEvent);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (11|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			    if (_errno == 0) {

				let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);
				let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
				let flags = msg2.buf[20] | (msg2.buf[21] << 8) | (msg2.buf[22] << 16) |  (msg2.buf[23] << 24);
				let mode = msg2.buf[24] | (msg2.buf[25] << 8);
				let type = msg2.buf[26];
				let major = msg2.buf[28] | (msg2.buf[29] << 8);
				let minor = msg2.buf[30] | (msg2.buf[31] << 8);
				let peer = UTF8ArrayToString(msg2.buf, 32, 108);

				//console.log("__syscall_openat: peer=%s", peer);

				var desc = {

				    fd: fd,
				    remote_fd: remote_fd,
				    flags: flags,
				    mode: mode,
				    peer: peer,
				    type: type,
				    major: major,
				    minor: minor,
				    
				    error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				    peers: {},
				    pending: [],
				    recv_queue: [],
				    name: null,
				    bc: null,
				};

				Module['fd_table'][fd] = desc;

				//console.log(Module['fd_table']);

				wakeUp(fd);
			    }
			    else {

				wakeUp(-_errno);
			    }

			return 0;
		    }

		    return -1;
		});

		let msg = {

		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};
		
		bc.postMessage(msg);
	    }
	});

	//console.log("openat: ret="+ret);

	return ret;
	
    /*path = SYSCALLS.getStr(path);
    path = SYSCALLS.calculateAt(dirfd, path);
    var mode = varargs ? SYSCALLS.get() : 0;
    return FS.open(path, flags, mode).fd;*/
    },
  __syscall_mkdirat__sig: 'iipi',
  __syscall_mkdirat: function(dirfd, path, mode) {
#if SYSCALL_DEBUG
    dbg('warning: untested syscall');
#endif
    path = SYSCALLS.getStr(path);
    path = SYSCALLS.calculateAt(dirfd, path);
    // remove a trailing slash, if one - /a/b/ has basename of '', but
    // we want to create b in the context of this function
    path = PATH.normalize(path);
    if (path[path.length-1] === '/') path = path.substr(0, path.length-1);
    FS.mkdir(path, mode, 0);
    return 0;
  },
  __syscall_mknodat__sig: 'iipii',
  __syscall_mknodat: function(dirfd, path, mode, dev) {
#if SYSCALL_DEBUG
    dbg('warning: untested syscall');
#endif
    path = SYSCALLS.getStr(path);
    path = SYSCALLS.calculateAt(dirfd, path);
    // we don't want this in the JS API as it uses mknod to create all nodes.
    switch (mode & {{{ cDefine('S_IFMT') }}}) {
      case {{{ cDefine('S_IFREG') }}}:
      case {{{ cDefine('S_IFCHR') }}}:
      case {{{ cDefine('S_IFBLK') }}}:
      case {{{ cDefine('S_IFIFO') }}}:
      case {{{ cDefine('S_IFSOCK') }}}:
        break;
      default: return -{{{ cDefine('EINVAL') }}};
    }
    FS.mknod(path, mode, dev);
    return 0;
  },
  __syscall_fchownat__sig: 'iipiii',
  __syscall_fchownat: function(dirfd, path, owner, group, flags) {
#if SYSCALL_DEBUG
    dbg('warning: untested syscall');
#endif
    path = SYSCALLS.getStr(path);
    var nofollow = flags & {{{ cDefine('AT_SYMLINK_NOFOLLOW') }}};
    flags = flags & (~{{{ cDefine('AT_SYMLINK_NOFOLLOW') }}});
#if ASSERTIONS
    assert(flags === 0);
#endif
    path = SYSCALLS.calculateAt(dirfd, path);
    (nofollow ? FS.lchown : FS.chown)(path, owner, group);
    return 0;
  },
  __syscall_newfstatat__sig: 'iippi',
    __syscall_newfstatat: function(dirfd, path, buf, flags) {

	//console.log("__syscall_newfstatat");
	
	/* Modified by Benoit Baudaux 8/2/2023 */
    /*path = SYSCALLS.getStr(path);
    var nofollow = flags & {{{ cDefine('AT_SYMLINK_NOFOLLOW') }}};
    var allowEmpty = flags & {{{ cDefine('AT_EMPTY_PATH') }}};
    flags = flags & (~{{{ cDefine('AT_SYMLINK_NOFOLLOW') | cDefine('AT_EMPTY_PATH') }}});
#if ASSERTIONS
    assert(!flags, flags);
#endif
    path = SYSCALLS.calculateAt(dirfd, path, allowEmpty);
    return SYSCALLS.doStat(nofollow ? FS.lstat : FS.stat, path, buf);*/
  },
  __syscall_unlinkat__sig: 'iipi',
  __syscall_unlinkat: function(dirfd, path, flags) {
    path = SYSCALLS.getStr(path);
    path = SYSCALLS.calculateAt(dirfd, path);
    if (flags === 0) {
      FS.unlink(path);
    } else if (flags === {{{ cDefine('AT_REMOVEDIR') }}}) {
      FS.rmdir(path);
    } else {
      abort('Invalid flags passed to unlinkat');
    }
    return 0;
  },
  __syscall_renameat__sig: 'iipip',
  __syscall_renameat: function(olddirfd, oldpath, newdirfd, newpath) {
    oldpath = SYSCALLS.getStr(oldpath);
    newpath = SYSCALLS.getStr(newpath);
    oldpath = SYSCALLS.calculateAt(olddirfd, oldpath);
    newpath = SYSCALLS.calculateAt(newdirfd, newpath);
    FS.rename(oldpath, newpath);
    return 0;
  },
  __syscall_linkat__nothrow: true,
  __syscall_linkat__proxy: false,
  __syscall_linkat: function(olddirfd, oldpath, newdirfd, newpath, flags) {
    return -{{{ cDefine('EMLINK') }}}; // no hardlinks for us
  },
  __syscall_symlinkat: function(target, newdirfd, linkpath) {
#if SYSCALL_DEBUG
    dbg('warning: untested syscall');
#endif
    linkpath = SYSCALLS.calculateAt(newdirfd, linkpath);
    FS.symlink(target, linkpath);
    return 0;
  },
  __syscall_fchmodat__sig: 'iipip',
  __syscall_fchmodat: function(dirfd, path, mode, varargs) {
#if SYSCALL_DEBUG
    dbg('warning: untested syscall');
#endif
    path = SYSCALLS.getStr(path);
    path = SYSCALLS.calculateAt(dirfd, path);
    FS.chmod(path, mode);
    return 0;
  },
  __syscall_faccessat__sig: 'iipii',
  __syscall_faccessat: function(dirfd, path, amode, flags) {
#if SYSCALL_DEBUG
    dbg('warning: untested syscall');
#endif
    path = SYSCALLS.getStr(path);
#if ASSERTIONS
    assert(flags === 0);
#endif
    path = SYSCALLS.calculateAt(dirfd, path);
    if (amode & ~{{{ cDefine('S_IRWXO') }}}) {
      // need a valid mode
      return -{{{ cDefine('EINVAL') }}};
    }
    var lookup = FS.lookupPath(path, { follow: true });
    var node = lookup.node;
    if (!node) {
      return -{{{ cDefine('ENOENT') }}};
    }
    var perms = '';
    if (amode & {{{ cDefine('R_OK') }}}) perms += 'r';
    if (amode & {{{ cDefine('W_OK') }}}) perms += 'w';
    if (amode & {{{ cDefine('X_OK') }}}) perms += 'x';
    if (perms /* otherwise, they've just passed F_OK */ && FS.nodePermissions(node, perms)) {
      return -{{{ cDefine('EACCES') }}};
    }
    return 0;
  },
  __syscall_utimensat__sig: 'iippi',
  __syscall_utimensat__deps: ['$readI53FromI64'],
  __syscall_utimensat: function(dirfd, path, times, flags) {
    path = SYSCALLS.getStr(path);
#if ASSERTIONS
    assert(flags === 0);
#endif
    path = SYSCALLS.calculateAt(dirfd, path, true);
    if (!times) {
      var atime = Date.now();
      var mtime = atime;
    } else {
      var seconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_sec, 'i53') }}};
      var nanoseconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_nsec, 'i32') }}};
      atime = (seconds*1000) + (nanoseconds/(1000*1000));
      times += {{{ C_STRUCTS.timespec.__size__ }}};
      seconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_sec, 'i53') }}};
      nanoseconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_nsec, 'i32') }}};
      mtime = (seconds*1000) + (nanoseconds/(1000*1000));
    }
    FS.utime(path, atime, mtime);
    return 0;
  },
  __syscall_fallocate__deps: i53ConversionDeps,
  __syscall_fallocate: function(fd, mode, {{{ defineI64Param('offset') }}}, {{{ defineI64Param('len') }}}) {
    {{{ receiveI64ParamAsI53('offset', -cDefine('EOVERFLOW')) }}}
    {{{ receiveI64ParamAsI53('len', -cDefine('EOVERFLOW')) }}}
    var stream = SYSCALLS.getStreamFromFD(fd)
#if ASSERTIONS
    assert(mode === 0);
#endif
    FS.allocate(stream, offset, len);
    return 0;
  },
  __syscall_dup3: function(fd, suggestFD, flags) {
    var old = SYSCALLS.getStreamFromFD(fd);
#if ASSERTIONS
    assert(!flags);
#endif
    if (old.fd === suggestFD) return -{{{ cDefine('EINVAL') }}};
    var suggest = FS.getStream(suggestFD);
    if (suggest) FS.close(suggest);
    return FS.createStream(old, suggestFD, suggestFD + 1).fd;
  },
    // Modified by Benoit Baudaux 20/11/2020
    __syscall_fork: function() {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    //console.log("fork: pid="+pid);

	    function do_fork() {

		let channel = 'channel.1.'+Module.child_pid+'.fork';

		if (!Module[channel]) {

		    Module[channel] = new BroadcastChannel('channel.1.'+Module.child_pid+'.fork');

		    Module[channel].onmessage = (function(_ch,_pid) {

			return ((messageEvent) => {

			    if (messageEvent.data == "continue_fork") {

				//console.log("continue_fork");

				if (Module[_ch]) {

				    Module[_ch].postMessage(Module.HEAPU8);

				    Asyncify.stackTop = stackSave();
				    Asyncify.stackBase = _emscripten_stack_get_base();
				    Asyncify.stackEnd = _emscripten_stack_get_end();
				    
				    Module[_ch].postMessage(JSON.stringify(Asyncify));
				}
			    }
			    else if (messageEvent.data == "end_fork") {

				Module[_ch].close();

				wakeUp(_pid);
			    }

			});
		    })(channel,Module.child_pid);

		    let msg = {

			type: 3,   // fork
			pid: Module.child_pid
		    };

		    window.parent.postMessage(msg);
		}
	    };

	    if (pid == 1) {  // Fork called by resmgr

		if (!Module.child_pid) {

		    // Reserve 1 for resmgr, so start at 2
		    
		    Module.child_pid = 2;
		}
		else {

		    Module.child_pid += 1;
		}

		do_fork();
	    }
	    else {

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		//console.log(bc);

		let buf = new Uint8Array(256);

		buf[0] = 7; // FORK

		/*//padding
		  buf[1] = 0;
		  buf[2] = 0;
		  buf[3] = 0;*/

		// pid
		buf[4] = pid & 0xff;
		buf[5] = (pid >> 8) & 0xff;
		buf[6] = (pid >> 16) & 0xff;
		buf[7] = (pid >> 24) & 0xff;

		// errno
		buf[8] = 0x0;
		buf[9] = 0x0;
		buf[10] = 0x0;
		buf[11] = 0x0;

		// child pid
		buf[12] = 0x0;
		buf[13] = 0x0;
		buf[14] = 0x0;
		buf[15] = 0x0;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		    
		    //console.log(messageEvent);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (7|0x80)) {

			Module['rcv_bc_channel'].set_handler(null);

			Module.child_pid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			do_fork();

			return 0;
		    }

		    return -1;
		});

		let msg = {

		    from: Module['rcv_bc_channel'].name,
		    buf: buf,
		    len: 256
		};
		
		bc.postMessage(msg);
	    }
	});

	return ret;
    },
    // Modified by Benoit Baudaux 22/12/2020
    __syscall_execve__sig: 'ippp',
    __syscall_execve: function(pathname, argv, envp) {

	//console.log("__syscall_execve: argv="+argv+", envp="+envp);
	
	/* Modified by Benoit Baudaux 19/03/2023 */

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_exec = (path) => {
		
		console.log("do_exec: "+path);
		
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

		// Copy args in buf

		let i = 0;

		for (let offset = 0; ; offset += 4) {

		    let arg = Module.HEAPU8[argv+offset] | (Module.HEAPU8[argv+offset+1] << 8) | (Module.HEAPU8[argv+offset+2] << 16) |  (Module.HEAPU8[argv+offset+3] << 24);

		    if (!arg)
			break;

		    let j;

		    for (j = 0; Module.HEAPU8[arg+j]; j++) {

			buf[16+i+j] = Module.HEAPU8[arg+j];
		    }
		    
		    buf[16+i+j] = 0;
		    j++;

		    i += j;
		}

		buf[12] = i & 0xff;
		buf[13] = (i >> 8) & 0xff;
		buf[14] = (i >> 16) & 0xff;
		buf[15] = (i >> 24) & 0xff;

		// Copy env in buf

		let e = 16 + i;
		let f = e + 8; // keep space for count and size (in that order)

		i = 0;

		let count = 0;

		for (let offset = 0; ; offset += 4) {

		    let str = Module.HEAPU8[envp+offset] | (Module.HEAPU8[envp+offset+1] << 8) | (Module.HEAPU8[envp+offset+2] << 16) |  (Module.HEAPU8[envp+offset+3] << 24);

		    if (!str)
			break;

		    count++;

		    let j;

		    for (j = 0; Module.HEAPU8[str+j]; j++) {

			buf[f+i+j] = Module.HEAPU8[str+j];
		    }
		    
		    buf[f+i+j] = 0;
		    j++;

		    i += j;
		}

		buf[e] = count & 0xff;
		buf[e+1] = (count >> 8) & 0xff;
		buf[e+2] = (count >> 16) & 0xff;
		buf[e+3] = (count >> 24) & 0xff;

		buf[e+4] = i & 0xff;
		buf[e+5] = (i >> 8) & 0xff;
		buf[e+6] = (i >> 16) & 0xff;
		buf[e+7] = (i >> 24) & 0xff;

		// rcv_bc_channel is not registered if it is a fork of resmgr

		let rcv_bc = Module['rcv_bc_channel'] || new BroadcastChannel("channel.process."+window.frameElement.getAttribute('pid'));

		let msg = {

		    from: rcv_bc.name,
		    buf: buf,
		    len: buf_size
		};

		let bc;

		// Module.get_broadcast_channel is not registered if it is a fork of resmgr
		
		if (Module.get_broadcast_channel)
		    bc = Module.get_broadcast_channel("/var/resmgr.peer");
		else
		    bc = new BroadcastChannel("/var/resmgr.peer");

		bc.postMessage(msg);
		
		// name property of window for process to be loaded fully and args and env to be recovered
		window.name = "exec";
		
		window.frameElement.src = "/netfs" + path+"/exa/exa.html";
	    };

	    let path = SYSCALLS.getStr(pathname);

	    if (path.charAt(0) == "/") {
		
		do_exec(path);
		return;
	    }

	    let buf_size = 256;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 34; // GETCWD
	    
	    /*//padding
	      buf[1] = 0;
	      buf[2] = 0;
	      buf[3] = 0;*/

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);
		
		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (34|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_stat64: _errno="+_errno);

		    if (_errno == 0) {

			let len = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			let cwd = UTF8ArrayToString(msg2.buf, 16, 1024);

			let sep = "";

			if ( (cwd.length > 0) && (cwd.slice(-1) != "/") && (path.length > 0) && (path.charAt(0) != "/") )
			    sep = "/";

			console.log("cwd:"+cwd);
			
			do_exec(cwd+sep+path);
		    }
		    else {

			wakeUp(-1);
		    }

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");
	    
	    bc.postMessage(msg);

	});

	
    },

    /* Modified by Benoit Baudaux 5/1/2023 */
    __syscall_write__sig: 'iipi',
    __syscall_write: function(fd, buf, count) {
	
	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_write = () => {
	
		let len = count;

		let buf_size = 20+len;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 13; // WRITE

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;

		// remote_fd
		buf2[12] = remote_fd & 0xff;
		buf2[13] = (remote_fd >> 8) & 0xff;
		buf2[14] = (remote_fd >> 16) & 0xff;
		buf2[15] = (remote_fd >> 24) & 0xff;

		// len
		buf2[16] = len & 0xff;
		buf2[17] = (len >> 8) & 0xff;
		buf2[18] = (len >> 16) & 0xff;
		buf2[19] = (len >> 24) & 0xff;

		buf2.set(HEAPU8.slice(buf,buf+len),20);

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (13|0x80)) {
			
			let bytes_written = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			
			wakeUp(bytes_written);

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {

		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
		driver_bc.postMessage(msg);
	    };

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_write();
	    }
	    else {
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;

			    do_write();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }
	});
    
    return ret;
    },
    /* Modified by Benoit Baudaux 8/1/2023 */
    __syscall_writev__sig: 'iipp',
    __syscall_writev: function(fd, iov, iovcnt) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_writev = () => {
	
		let len = 0;

		let iov2 = iov;

		for (var i = 0; i < iovcnt; i++) {
		    len += {{{ makeGetValue('iov2', C_STRUCTS.iovec.iov_len, '*') }}};
		    iov2 += {{{ C_STRUCTS.iovec.__size__ }}};
		}

		let buf_size = 20+len;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 13; // WRITE

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;

		// remote_fd
		buf2[12] = remote_fd & 0xff;
		buf2[13] = (remote_fd >> 8) & 0xff;
		buf2[14] = (remote_fd >> 16) & 0xff;
		buf2[15] = (remote_fd >> 24) & 0xff;

		// len
		buf2[16] = len & 0xff;
		buf2[17] = (len >> 8) & 0xff;
		buf2[18] = (len >> 16) & 0xff;
		buf2[19] = (len >> 24) & 0xff;

		buf_size = 20;

		iov2 = iov;

		for (var i = 0; i < iovcnt; i++) {
		    let ptr = {{{ makeGetValue('iov2', C_STRUCTS.iovec.iov_base, '*') }}};
		    let l = {{{ makeGetValue('iov2', C_STRUCTS.iovec.iov_len, '*') }}};
		    
		    if (l > 0)
			buf2.set(HEAPU8.slice(ptr,ptr+l), buf_size);
		    
		    buf_size += l;
		    
		    iov2 += {{{ C_STRUCTS.iovec.__size__ }}};
		}

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (13|0x80)) {

			let bytes_written = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			
			wakeUp(bytes_written);

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {

		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
		driver_bc.postMessage(msg);
	    };

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_writev();
	    }
	    else {
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;

			    do_writev();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }
	});
    
    return ret;
    },
    /* Modified by Benoit Baudaux 9/1/2023 */
    __syscall_getpid__sig: 'i',
    __syscall_getpid: function() {

	return parseInt(window.frameElement.getAttribute('pid'));
    },
    /* Modified by Benoit Baudaux 11/1/2023 */
    __syscall_close__sig: 'ii',
    __syscall_close: function(fd) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 16;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 15; // CLOSE

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // fd
	    buf2[12] = fd & 0xff;
	    buf2[13] = (fd >> 8) & 0xff;
	    buf2[14] = (fd >> 16) & 0xff;
	    buf2[15] = (fd >> 24) & 0xff;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (15|0x80)) {

		    //console.log(messageEvent);

		    Module['fd_table'][fd] = null;

		    wakeUp(0); // TODO

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);

	});
	
	return ret;
    },
    /* Modified by Benoit Baudaux 13/1/2023 */
    __syscall_setsid__sig: 'i',
    __syscall_setsid: function() {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 16;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 16; // SETSID

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // sid
	    buf2[12] = 0;
	    buf2[13] = 0;
	    buf2[14] = 0;
	    buf2[15] = 0;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (16|0x80)) {

		    //console.log(messageEvent);

		    let sid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

		    Module['sid'] = sid;

		    wakeUp(sid);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);

	});
	
	return ret;
    },
    /* Modified by Benoit Baudaux 22/1/2023 */
    __syscall_getsid__sig: 'i',
    __syscall_getsid: function(req_pid) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 20;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 18; // GETSID

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // requested pid
	    buf2[12] = req_pid & 0xff;
	    buf2[13] = (req_pid >> 8) & 0xff;
	    buf2[14] = (req_pid >> 16) & 0xff;
	    buf2[15] = (req_pid >> 24) & 0xff;

	    // sid
	    buf2[16] = 0;
	    buf2[17] = 0;
	    buf2[18] = 0;
	    buf2[19] = 0;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (18|0x80)) {

		    //console.log(messageEvent);
		    
		    let sid = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    wakeUp(sid);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);

	});
	
	return ret;
    },
    /* Modified by Benoit Baudaux 14/1/2023 */
    __syscall_read__sig: 'iipi',
    __syscall_read: function(fd, buf, count) {

	console.log("__syscall_read: fd="+fd);

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_read = () => {
		
		if (Module['fd_table'][fd].timerfd) {

		    if (count < 8) {

			wakeUp(-1);
		    }
		    else {
			Module.HEAPU8[buf] = Module['fd_table'][fd].counter & 0xff;
			Module.HEAPU8[buf+1] = (Module['fd_table'][fd].counter >> 8) & 0xff;
			Module.HEAPU8[buf+2] = (Module['fd_table'][fd].counter >> 16) & 0xff;
			Module.HEAPU8[buf+3] = (Module['fd_table'][fd].counter >> 24) & 0xff;
			Module.HEAPU8[buf+4] = 0;
			Module.HEAPU8[buf+5] = 0;
			Module.HEAPU8[buf+6] = 0;
			Module.HEAPU8[buf+7] = 0;

			Module['fd_table'][fd].counter = 0;

			wakeUp(8);
		    }

		    return;
		}

		let len = count;
		
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 12; // READ

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;

		// remote_fd
		buf2[12] = remote_fd & 0xff;
		buf2[13] = (remote_fd >> 8) & 0xff;
		buf2[14] = (remote_fd >> 16) & 0xff;
		buf2[15] = (remote_fd >> 24) & 0xff;

		// len
		buf2[16] = len & 0xff;
		buf2[17] = (len >> 8) & 0xff;
		buf2[18] = (len >> 16) & 0xff;
		buf2[19] = (len >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (12|0x80)) {

			let bytes_read = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			//console.log("bytes_read: "+bytes_read);

			Module.HEAPU8.set(msg2.buf.slice(20, 20+bytes_read), buf);
			
			wakeUp(bytes_read);

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
		driver_bc.postMessage(msg);
	    };

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_read();
	    }
	    else {
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;

			    do_read();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }
	});
    
    return ret;
    },
    __syscall_readv__sig: 'iippp',
    __syscall_readv: function(fd, iov, iovcnt) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let count = 0;

	    for (let i = 0; i < iovcnt; i++) {

		count += Module.HEAPU8[iov+8*i+4] | (Module.HEAPU8[iov+8*i+5] << 8) | (Module.HEAPU8[iov+8*i+6] << 16) |  (Module.HEAPU8[iov+8*i+7] << 24)
	    }

	    console.log("__syscall_readv: iovcnt="+iovcnt+", count="+count);

	    let do_readv = () => {

		let len = count;
		
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 12; // READ

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;

		// remote_fd
		buf2[12] = remote_fd & 0xff;
		buf2[13] = (remote_fd >> 8) & 0xff;
		buf2[14] = (remote_fd >> 16) & 0xff;
		buf2[15] = (remote_fd >> 24) & 0xff;

		// len
		buf2[16] = len & 0xff;
		buf2[17] = (len >> 8) & 0xff;
		buf2[18] = (len >> 16) & 0xff;
		buf2[19] = (len >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (12|0x80)) {

			let bytes_read = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			console.log("__syscall_readv: bytes_read="+bytes_read);

			let offset = 0;

			for (let i = 0; i < iovcnt; i++) {

			    let len =  Module.HEAPU8[iov+8*i+4] | (Module.HEAPU8[iov+8*i+5] << 8) | (Module.HEAPU8[iov+8*i+6] << 16) |  (Module.HEAPU8[iov+8*i+7] << 24);

			    console.log("__syscall_readv: "+i+", len="+len);
			    
			    let len2 = ((offset+len) <= bytes_read)?len:bytes_read-offset;

			    console.log("__syscall_readv: "+i+", len2="+len2);

			    if (len2 > 0) {
				let ptr =  Module.HEAPU8[iov+8*i] | (Module.HEAPU8[iov+8*i+1] << 8) | (Module.HEAPU8[iov+8*i+2] << 16) |  (Module.HEAPU8[iov+8*i+3] << 24);

				Module.HEAPU8.set(msg2.buf.slice(20+offset, 20+offset+len2), ptr);
			    }
			    else {

				break;
			    }

			    offset += len2;

			    if (offset >= bytes_read)
				break;
			}
			
			wakeUp(bytes_read);

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
		driver_bc.postMessage(msg);
	    };

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_readv();
	    }
	    else {
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;

			    do_readv();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }
	});
    
    return ret;
    },
    __syscall_pause__sig: 'i',
    __syscall_pause: function() {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    // TODO
	});
				       
	return ret;
    },
    __syscall_getpgid__sig: 'ii',
    __syscall_getpgid: function(req_pid) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 20;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 21; // GETPGID

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // requested pid
	    buf2[12] = req_pid & 0xff;
	    buf2[13] = (req_pid >> 8) & 0xff;
	    buf2[14] = (req_pid >> 16) & 0xff;
	    buf2[15] = (req_pid >> 24) & 0xff;

	    // pgid
	    buf2[16] = 0;
	    buf2[17] = 0;
	    buf2[18] = 0;
	    buf2[19] = 0;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (21|0x80)) {

		    //console.log(messageEvent);
		    
		    let pgid = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    wakeUp(pgid);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	});
				       
	return ret;
    },
    __syscall_setpgid__sig: 'iii',
    __syscall_setpgid: function(req_pid, pgid) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 20;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 22; // SETPGID

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // requested pid
	    buf2[12] = req_pid & 0xff;
	    buf2[13] = (req_pid >> 8) & 0xff;
	    buf2[14] = (req_pid >> 16) & 0xff;
	    buf2[15] = (req_pid >> 24) & 0xff;

	    // pgid
	    buf2[16] = pgid & 0xff;
	    buf2[17] = (pgid >> 8) & 0xff;
	    buf2[18] = (pgid >> 16) & 0xff;
	    buf2[19] = (pgid >> 24) & 0xff;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (22|0x80)) {

		    //console.log(messageEvent);
		    
		    wakeUp(0);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	});
				       
	return ret;
    },
    __syscall_getppid__sig: 'i',
    __syscall_getppid: function() {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 16;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 20; // GETPPID

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // ppid
	    buf2[12] = 0;
	    buf2[13] = 0;
	    buf2[14] = 0;
	    buf2[15] = 0;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (20|0x80)) {

		    //console.log(messageEvent);
		    
		    let ppid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

		    wakeUp(ppid);

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	});
				       
	return ret;
    },
    __syscall_readlinkat__sig: 'iippi',
    __syscall_readlinkat: function(dirfd, path, buf, bufsize) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 1256;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 27; // READLINK

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    buf2[12] = dirfd & 0xff;
	    buf2[13] = (dirfd >> 8) & 0xff;
	    buf2[14] = (dirfd >> 16) & 0xff;
	    buf2[15] = (dirfd >> 24) & 0xff;

	    let path_len = 0;

	    while (Module.HEAPU8[path+path_len]) {

		path_len++;
	    }

	    path_len++;

	    buf2.set(Module.HEAPU8.slice(path, path+path_len), 20);

	    buf2[16] = path_len & 0xff;
	    buf2[17] = (path_len >> 8) & 0xff;
	    buf2[18] = (path_len >> 16) & 0xff;
	    buf2[19] = (path_len >> 24) & 0xff;
	    
	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (27|0x80)) {

		    //console.log(messageEvent);
		    
		    // TODO: check bufsize

		    let len = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    Module.HEAPU8.set(msg2.buf.slice(20, 20+len), buf);

		    wakeUp(len-1); // Remove last zero frol len

		    return 0;
		}

		return -1;
	    });

	    let msg = {

		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	    
	});

	return ret;
	
	},
    __syscall_pselect6__sig: 'iippppp',
    __syscall_pselect6: function(nfds, readfds, writefds, exceptfds, timeout, sigmaks) {

	//let end = -1;

	if (timeout) {

	    let s = Module.HEAPU8[timeout] | (Module.HEAPU8[timeout+1] << 8) | (Module.HEAPU8[timeout+2] << 16) |  (Module.HEAPU8[timeout+3] << 24);

	    let ns = Module.HEAPU8[timeout+4] | (Module.HEAPU8[timeout+5] << 8) | (Module.HEAPU8[timeout+6] << 16) |  (Module.HEAPU8[timeout+7] << 24);

	    //end = 1000*s + 1000000*ns;

	    //console.log("__syscall_pselect6: timeout s="+s+", ns="+ns);
	}
	else {

	    //console.log("__syscall_pselect6: no timeout");
	}

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let readfds_array = [];

	    if (readfds) {

		for (let i=0; i < nfds; i++) {

		    if (Module.HEAPU8[readfds+Math.floor(i/8)] & (1 << (i % 8))) {

			readfds_array.push(i);
		    }
		}
	    }

	    let writefds_array = [];

	    if (writefds) {

		for (let i=0; i < nfds; i++) {

		    if (Module.HEAPU8[writefds+Math.floor(i/8)] & (1 << (i % 8))) {

			writefds_array.push(i);
		    }
		}
	    }

	    let do_select = (fd, rw, start) => {

		let buf_size = 256;
	
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 31; // SELECT

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		// rw
		buf2[16] = rw & 0xff;
		buf2[17] = (rw >> 8) & 0xff;
		buf2[18] = (rw >> 16) & 0xff;
		buf2[19] = (rw >> 24) & 0xff;
		
		let start_stop = 1;
		
		// start_stop
		buf2[20] = start & 0xff;
		buf2[21] = (start >> 8) & 0xff;
		buf2[22] = (start >> 16) & 0xff;
		buf2[23] = (start >> 24) & 0xff;

		if (Module['fd_table'][fd].timerfd) { // timerfd

		    Module['fd_table'][fd].select(fd, rw, start, function(fd, rw) {

			notif_select(fd, rw);
		    });
		}
		else if (Module['fd_table'][fd].sock_ops) { // socket

		    Module['fd_table'][fd].sock_ops.select(getSocketFromFD(fd), fd, rw, start, function(fd, rw) {

			notif_select(fd, rw);
		    });
		}
		else { // any other type of fd (remote)

		    let remote_fd = Module['fd_table'][fd].remote_fd;

		    // remote fd
		    buf2[24] = remote_fd & 0xff;
		    buf2[25] = (remote_fd >> 8) & 0xff;
		    buf2[26] = (remote_fd >> 16) & 0xff;
		    buf2[27] = (remote_fd >> 24) & 0xff;

		    let msg = {
			
			from: Module['rcv_bc_channel'].name,
			buf: buf2,
			len: buf_size
		    };

		    let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		    
		    driver_bc.postMessage(msg);
		}
	    };

	    let notif_select = (fd, rw) => {

		// Stop select for readfds
		
		for (let readfd in readfds_array) {

		    if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

			do_select(readfd, 0, 0);
		    }
		}

		// Stop select for writefds

		for (let writefd in writefds_array) {

		    if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

			do_select(writefd, 1, 0);
		    }
		}
		
		if (readfds) {
		    for (let i=0; i < nfds; i++) {

			Module.HEAPU8[readfds+Math.floor(i/8)] = 0;
		    }
		}

		if (writefds) {
		    for (let i=0; i < nfds; i++) {

			Module.HEAPU8[writefds+Math.floor(i/8)] = 0;
		    }
		}

		if (rw && writefds) {

		    Module.HEAPU8[writefds+Math.floor(fd/8)] = 1 << (fd % 8);
		}
		else if (readfds) {

		    Module.HEAPU8[readfds+Math.floor(fd/8)] = 1 << (fd % 8);
		}

		wakeUp(1);
	    };

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;
		
		if (msg2.buf[0] == (31|0x80)) {

		    let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

		    let rw = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    notif_select(fd, rw);

		    return 0;
		}
		else {

		    return -1;
		}
	    });

	    let i = 0;

	    // Start select for readfds
	    
	    for (let readfd in readfds_array) {

		if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

		    i++;
		    do_select(readfd, 0, 1);
		}
	    }
	    
	    // Start select for writefds

	    for (let writefd in writefds_array) {

		if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

		    i++;
		    do_select(writefd, 1, 1);
		}
	    }

	    if (i == 0) { // no fd for select

		wakeUp(0);
	    }
	});

	return ret;
    },
    __syscall_timerfd_create__sig: 'iii',
    __syscall_timerfd_create: function(clockid, flags) {

	let ret = Asyncify.handleSleep(function (wakeUp) {
	    
	    let buf_size = 20;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 33; // TIMERFD_CREATE

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // clockid
	    buf2[12] = clockid & 0xff;
	    buf2[13] = (clockid >> 8) & 0xff;
	    buf2[14] = (clockid >> 16) & 0xff;
	    buf2[15] = (clockid >> 24) & 0xff;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (33|0x80)) {

		    let fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    var desc = {

			timerfd: fd,
			counter: 0,
			increase_counter: function() {

			    this.counter++;

			    if (this.notif_select)
				this.notif_select(this.select_fd, this.select_rw);
			},
			select: function (fd, rw, start_stop, notif_select) {

			    if (start_stop) {

				if (this.counter > 0) {

				    this.notif_select = null;
				    notif_select(fd, rw);
				}
				else {

				    this.select_fd = fd;
				    this.select_rw = rw;
				    this.notif_select = notif_select;
				}
			    }
			    else {

				this.notif_select = null;
			    }
			}
		    };

		    Module['fd_table'][fd] = desc;

		    wakeUp(fd);

		    return 0;
		}

		return -1;
	    });

	    let msg = {
		
		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	});

	return ret;
	
    },
    __syscall_timerfd_settime__sig: 'iiipp',
    __syscall_timerfd_settime: function(fd, flags, new_value, curr_value) {

	//console.log('__syscall_timerfd_settime: fd='+fd+' flags='+flags+' new_value='+new_value);

	const int_sec = Module.HEAPU8[new_value] | (Module.HEAPU8[new_value+1] << 8) | (Module.HEAPU8[new_value+2] << 16) |  (Module.HEAPU8[new_value+3] << 24);
	const int_nsec = Module.HEAPU8[new_value+8] | (Module.HEAPU8[new_value+9] << 8) | (Module.HEAPU8[new_value+10] << 16) |  (Module.HEAPU8[new_value+11] << 24);
	const val_sec = Module.HEAPU8[new_value+16] | (Module.HEAPU8[new_value+17] << 8) | (Module.HEAPU8[new_value+18] << 16) |  (Module.HEAPU8[new_value+19] << 24);
	const val_nsec = Module.HEAPU8[new_value+24] | (Module.HEAPU8[new_value+25] << 8) | (Module.HEAPU8[new_value+26] << 16) |  (Module.HEAPU8[new_value+27] << 24);

	Module['fd_table'][fd].int_msec = int_sec * 1000 + int_nsec / 1000000;
	Module['fd_table'][fd].val_msec = val_sec * 1000 + val_nsec / 1000000;
	
	//console.log('__syscall_timerfd_settime: int='+int_sec+' '+int_nsec+' '+Module['fd_table'][fd].int_msec+', val='+val_sec+' '+val_nsec+' '+Module['fd_table'][fd].val_msec);

	if (Module['fd_table'][fd].val_msec) {

	    Module['fd_table'][fd].timeout_id = setTimeout(() => {

		Module['fd_table'][fd].increase_counter();

		if (Module['fd_table'][fd].int_msec) {

		    Module['fd_table'][fd].timeout_id = setInterval(() => {

			Module['fd_table'][fd].increase_counter();
			
		    }, Module['fd_table'][fd].int_msec);
		}
		
	    }, Module['fd_table'][fd].val_msec);
	}
	else {

	    clearTimeout(Module['fd_table'][fd].timeout_id);
	}
    },
    __syscall_timerfd_gettime__sig: 'iip',
    __syscall_timerfd_gettime: function(fd, curr_value) {

	//console.log('__syscall_timerfd_gettime: fd='+fd);
    },
    __syscall_wait4__sig: 'iipii',
    __syscall_wait4: function (wpid, wstatus, options, rusage) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    console.log("__syscall_wait4: wpid="+wpid+", options="+options);
	    
	    let buf_size = 24;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 37; // WAIT

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // wpid
	    buf2[12] = wpid & 0xff;
	    buf2[13] = (wpid >> 8) & 0xff;
	    buf2[14] = (wpid >> 16) & 0xff;
	    buf2[15] = (wpid >> 24) & 0xff;

	    // options
	    buf2[16] = options & 0xff;
	    buf2[17] = (options >> 8) & 0xff;
	    buf2[18] = (options >> 16) & 0xff;
	    buf2[19] = (options >> 24) & 0xff;

	    Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		Module['rcv_bc_channel'].set_handler(null);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (37|0x80)) {

		    let pid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

		    Module.HEAPU8.set(msg2.buf.slice(20, 20+4), wstatus);

		    wakeUp(pid);
		    
		    return 0;
		}

		return -1;
	    });

	    let msg = {
		
		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);
	});

	return ret;
    },
    __syscall_exit_group__sig: 'vi',
    __syscall_exit_group: function (status) {

	Asyncify.handleSleep(function (wakeUp) {

	    console.log("__syscall_exit_group");

	    let buf_size = 20;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 38; // EXIT

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // status
	    buf2[12] = status & 0xff;
	    buf2[13] = (status >> 8) & 0xff;
	    buf2[14] = (status >> 16) & 0xff;
	    buf2[15] = (status >> 24) & 0xff;
	    
	    let msg = {
		
		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);

	});
    },
    __syscall_exit__sig: 'vi',
    __syscall_exit: function (status) {

	Asyncify.handleSleep(function (wakeUp) {

	    console.log("__syscall_exit");

	    let buf_size = 20;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 38; // EXIT

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // status
	    buf2[12] = status & 0xff;
	    buf2[13] = (status >> 8) & 0xff;
	    buf2[14] = (status >> 16) & 0xff;
	    buf2[15] = (status >> 24) & 0xff;
	    
	    let msg = {
		
		from: Module['rcv_bc_channel'].name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);

	});
    },

    __syscall_lseek__sig: 'iiii',
    __syscall_lseek: function (fd, offset, whence) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_lseek = () => {

		let buf_size = 24;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 39; // SEEK

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;

		// remote_fd
		buf2[12] = remote_fd & 0xff;
		buf2[13] = (remote_fd >> 8) & 0xff;
		buf2[14] = (remote_fd >> 16) & 0xff;
		buf2[15] = (remote_fd >> 24) & 0xff;

		// offset
		buf2[16] = offset & 0xff;
		buf2[17] = (offset >> 8) & 0xff;
		buf2[18] = (offset >> 16) & 0xff;
		buf2[19] = (offset >> 24) & 0xff;

		// whence
		buf2[20] = whence & 0xff;
		buf2[21] = (whence >> 8) & 0xff;
		buf2[22] = (whence >> 16) & 0xff;
		buf2[23] = (whence >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (39|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			//console.log("bytes_read: "+bytes_read);
			
			wakeUp(-_errno);

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		
		driver_bc.postMessage(msg);
	    };

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_lseek();
	    }
	    else {
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		// fd
		buf2[12] = fd & 0xff;
		buf2[13] = (fd >> 8) & 0xff;
		buf2[14] = (fd >> 16) & 0xff;
		buf2[15] = (fd >> 24) & 0xff;

		Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    Module['rcv_bc_channel'].set_handler(null);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (26|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    let type = msg2.buf[20];
			    let major = msg2.buf[22] | (msg2.buf[23] << 8);
			    let peer = UTF8ArrayToString(msg2.buf, 24, 108);			    
			    var desc = {

				fd: fd,
				remote_fd: remote_fd,
				peer: peer,
				type: type,
				major: major,
				
				error: null, // Used in getsockopt for SOL_SOCKET/SO_ERROR test
				peers: {},
				pending: [],
				recv_queue: [],
				name: null,
				bc: null,
			    };

			    Module['fd_table'][fd] = desc;

			    do_lseek();
			}
			else {

			    wakeUp(-1);
			}

			return 0;
		    }
		    else {

			return -1;
		    }
		});

		let msg = {
		    
		    from: Module['rcv_bc_channel'].name,
		    buf: buf2,
		    len: buf_size
		};

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		bc.postMessage(msg);
	    }
	});

	return ret;
    },
};

function wrapSyscallFunction(x, library, isWasi) {
  if (x[0] === '$' || isJsLibraryConfigIdentifier(x)) {
    return;
  }

  var t = library[x];
  if (typeof t == 'string') return;
  t = t.toString();

  // If a syscall uses FS, but !SYSCALLS_REQUIRE_FILESYSTEM, then the user
  // has disabled the filesystem or we have proven some other way that this will
  // not be called in practice, and do not need that code.
  if (!SYSCALLS_REQUIRE_FILESYSTEM && t.includes('FS.')) {
    t = modifyFunction(t, function(name, args, body) {
      return 'function ' + name + '(' + args + ') {\n' +
             (ASSERTIONS ? "abort('it should not be possible to operate on streams when !SYSCALLS_REQUIRE_FILESYSTEM');\n" : '') +
             '}';
    });
  }

  var isVariadic = !isWasi && t.includes(', varargs');
#if SYSCALLS_REQUIRE_FILESYSTEM == 0
  var canThrow = false;
#else
  var canThrow = library[x + '__nothrow'] !== true;
#endif

  var pre = '', post = '';
  if (isVariadic) {
    pre += 'SYSCALLS.varargs = varargs;\n';
  }

#if SYSCALL_DEBUG
  if (isVariadic) {
    if (canThrow) {
      post += 'finally { SYSCALLS.varargs = undefined; }\n';
    } else {
      post += 'SYSCALLS.varargs = undefined;\n';
    }
  }
  pre += "dbg('syscall! " + x + ": [' + Array.prototype.slice.call(arguments) + ']');\n";
  pre += "var canWarn = true;\n";
  pre += "var ret = (function() {\n";
  post += "})();\n";
  post += "if (ret && ret < 0 && canWarn) {\n";
  post += "  dbg('error: syscall may have failed with ' + (-ret) + ' (' + ERRNO_MESSAGES[-ret] + ')');\n";
  post += "}\n";
  post += "dbg('syscall return: ' + ret);\n";
  post += "return ret;\n";
#endif
  delete library[x + '__nothrow'];
  var handler = '';
  if (canThrow) {
    pre += 'try {\n';
    handler +=
    "} catch (e) {\n" +
    "  if (typeof FS == 'undefined' || !(e instanceof FS.ErrnoError)) throw e;\n";
#if SYSCALL_DEBUG
    handler +=
    "  dbg('error: syscall failed with ' + e.errno + ' (' + ERRNO_MESSAGES[e.errno] + ')');\n" +
    "  canWarn = false;\n";
#endif
    // Musl syscalls are negated.
    if (isWasi) {
      handler += "  return e.errno;\n";
    } else {
      // Musl syscalls are negated.
      handler += "  return -e.errno;\n";
    }
    handler += "}\n";
  }
  post = handler + post;

  if (pre || post) {
    t = modifyFunction(t, function(name, args, body) {
      return `function ${name}(${args}) {\n${pre}${body}${post}}\n`;
    });
  }

  library[x] = eval('(' + t + ')');
  if (!library[x + '__deps']) library[x + '__deps'] = [];
  library[x + '__deps'].push('$SYSCALLS');
#if USE_PTHREADS
  // Most syscalls need to happen on the main JS thread (e.g. because the
  // filesystem is in JS and on that thread). Proxy synchronously to there.
  // There are some exceptions, syscalls that we know are ok to just run in
  // any thread; those are marked as not being proxied with
  //  __proxy: false
  // A syscall without a return value could perhaps be proxied asynchronously
  // instead of synchronously, and marked with
  //  __proxy: 'async'
  // (but essentially all syscalls do have return values).
  if (library[x + '__proxy'] === undefined) {
    library[x + '__proxy'] = 'sync';
  }
#endif
}

for (var x in SyscallsLibrary) {
  wrapSyscallFunction(x, SyscallsLibrary, false);
}

mergeInto(LibraryManager.library, SyscallsLibrary);
