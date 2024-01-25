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

	    let pid = Module.getpid();

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
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (35|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_stat64: _errno="+_errno);

		    wakeUp(-_errno);

		    return hid;
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

	/* Modified by Benoit Baudaux 25/01/2024 */

	let ret = Asyncify.handleSleep(function (wakeUp) {

	  let buf_size = 1256;
	  
	  let buf2 = new Uint8Array(buf_size);
	  
	  buf2[0] = 66; // RMDIR
	  
	  let pid = Module.getpid();
	  
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
	  
	  const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

	      let msg2 = messageEvent.data;

	      if (msg2.buf[0] == (66|0x80)) {

		  let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		  wakeUp(-_errno);

		  return hid;
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
	
    /*path = SYSCALLS.getStr(path);
    FS.rmdir(path);
    return 0;*/
  },
  __syscall_dup__sig: 'ii',
    __syscall_dup: function(fd) {
	/* Modified by Benoit Baudaux 22/1/2023 */
    /*var old = SYSCALLS.getStreamFromFD(fd);
      return FS.createStream(old, 0).fd;*/

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_dup = () => {

		let buf_size = 20;
		
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 19; // DUP

		let pid = Module.getpid();
		
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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (19|0x80)) {

			//console.log(messageEvent);

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {
			
			    let new_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			    Module['fd_table'][new_fd] = Module['fd_table'][fd];
			    
			    wakeUp(new_fd);
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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
	    }

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_dup();
	    }
	    else {
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    do_dup();

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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
    __syscall_dup2__sig: 'iii',
    __syscall_dup2: function(fd, new_fd) {
	/* Modified by Benoit Baudaux 22/1/2023 */
    /*var old = SYSCALLS.getStreamFromFD(fd);
      return FS.createStream(old, 0).fd;*/

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_dup2 = () => {

	    let buf_size = 20;
	
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 19; // DUP

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (19|0x80)) {

			//console.log(messageEvent);

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (_errno) {

			    wakeUp(-_errno);

			    return hid;
			}
			else if (new_fd != fd) {
			    
			    let new_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			    Module['fd_table'][new_fd] = Module['fd_table'][fd];
			    Module['fd_table'][new_fd].fd = new_fd;
			}

			wakeUp(new_fd);

			return hid;
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
	    }

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		do_dup2();
	    }
	    else {
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    do_dup2();

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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
  /*__syscall_pipe__deps: ['$PIPEFS'],
  __syscall_pipe__sig: 'ip',
  __syscall_pipe: function(fdPtr) {
    if (fdPtr == 0) {
      throw new FS.ErrnoError({{{ cDefine('EFAULT') }}});
    }

    var res = PIPEFS.createPipe();

    {{{ makeSetValue('fdPtr', 0, 'res.readable_fd', 'i32') }}};
    {{{ makeSetValue('fdPtr', 4, 'res.writable_fd', 'i32') }}};

    return 0;
    },*/
    __syscall_pipe2__sig: 'ipi',
    __syscall_pipe2: function(fdPtr, flags) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 24;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 47; // PIPE

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // flags
	    buf2[20] = flags & 0xff;
	    buf2[21] = (flags >> 8) & 0xff;
	    buf2[22] = (flags >> 16) & 0xff;
	    buf2[23] = (flags >> 24) & 0xff;

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (47|0x80)) {

		    //console.log(messageEvent);

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    if (!_errno) {

			let read_fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);
			let remote_read_fd = msg2.buf[24] | (msg2.buf[25] << 8) | (msg2.buf[26] << 16) |  (msg2.buf[27] << 24);
			let write_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			let remote_write_fd = msg2.buf[28] | (msg2.buf[29] << 8) | (msg2.buf[30] << 16) |  (msg2.buf[31] << 24);

			let type = msg2.buf[32];
			let major = msg2.buf[34] | (msg2.buf[35] << 8);
			let minor = msg2.buf[36] | (msg2.buf[37] << 8);
			let peer = UTF8ArrayToString(msg2.buf, 38, 108);

			let read_desc = {

			    fd: read_fd,
			    remote_fd: remote_read_fd,
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

			Module['fd_table'][read_fd] = read_desc;

			let write_desc = {

			    fd: write_fd,
			    remote_fd: remote_write_fd,
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

			Module['fd_table'][write_fd] = write_desc;

			//console.log(JSON.parse(JSON.stringify(Module['fd_table'])));

			Module.HEAPU8.set(msg2.buf.slice(12, 12+4), fdPtr);
			Module.HEAPU8.set(msg2.buf.slice(16, 16+4), fdPtr+4);	
		    }

		    wakeUp(-_errno);

		    return hid;
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

		let pid = Module.getpid();

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
		else if ( (op == {{{ cDefine('TIOCSPGRP') }}}) ||
			  (op == {{{ cDefine('FIONBIO') }}}) ) {

		    len = 4;
		}
		else if (op == {{{ cDefine('TIOCSWINSZ') }}})  {

		    len = 8;
		}
		else if (op == -1060350460) { // VIDIOC_G_FMT

		    len = 204;
		}
		else if (op == -1072409080) { // VIDIOC_REQBUFS
		    
		    len = 20;
		}
		else if (op == -1068476919) { // VIDIOC_QUERYBUF

		    len = 80;
		}
		else if (op == -1068476913) { // VIDIOC_QBUF

		    len = 80;
		}
		else if (op == 1074026002) { // VIDIOC_STREAMON

		    len = 4;
		}
		else if (op == -1068476911) { // VIDIOC_DQBUF

		    len = 80;
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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (14|0x80)) {

			let op2 = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			if (op2 != op) {

			    return -1;
			}

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			//console.log("__syscall_ioctl: op2=" +op2);
			//console.log("__syscall_ioctl: errno=" +_errno);

			//TODO : get len from driver itself
			let len = 0;

			switch(op2) {

			case {{{ cDefine('TIOCGWINSZ') }}}:

			    len = 8;
			    break;

			case {{{ cDefine('TCGETS') }}}:

			    len = 60; // 4*4+4+32+2*4;
			    break;

			case {{{ cDefine('TIOCGPGRP') }}}:
			case {{{ cDefine('TIOCGPTN') }}}:

			    len = 4;
			    break;

			case 0x4600:   // FBIOGET_VSCREENINFO

			    len = 88; // TODO
			    break;

			case 0x4602:   // FBIOGET_FSCREENINFO

			    len = 68; // TODO
			    break;

			case -2140645888: // VIDIOC_QUERYCAP

			    len = 104;
			    break;

			case -1060350460: // VIDIOC_G_FMT

			    len = 204;

			    let type = msg2.buf[24] | (msg2.buf[25] << 8) | (msg2.buf[26] << 16) |  (msg2.buf[27] << 24);

			    if (type == 1) { // V4L2_BUF_TYPE_VIDEO_CAPTURE


				let settings = Module.video0.mediaStream.getVideoTracks()[0].getSettings();

				msg2.buf[28] = settings.width & 0xff;
				msg2.buf[29] = (settings.width >> 8) & 0xff;
				msg2.buf[30] = (settings.width >> 16) & 0xff;
				msg2.buf[31] = (settings.width >> 24) & 0xff;

				msg2.buf[32] = settings.height & 0xff;
				msg2.buf[33] = (settings.height >> 8) & 0xff;
				msg2.buf[34] = (settings.height >> 16) & 0xff;
				msg2.buf[35] = (settings.height >> 24) & 0xff;
			    }
			    
			    break;

			case -1072409080: // VIDIOC_REQBUFS
			    {

			    len = 20;

			    let count = msg2.buf[24] | (msg2.buf[25] << 8) | (msg2.buf[26] << 16) |  (msg2.buf[27] << 24);

			    console.log("VIDIOC_REQBUFS: count="+count);

			    Module.video0.buffers = new Array();

			    let settings = Module.video0.mediaStream.getVideoTracks()[0].getSettings();

			    for (let i=0; i < count; i+=1) {

				let canvas = document.createElement("canvas");

				canvas.width = settings.width;
				canvas.height = settings.height;

				let length = canvas.width * canvas.height * 4;

				Module.video0.buffers.push({'canvas':canvas, 'length': length, 'state': 0}); // dequeued
			    }
			    
				break;
			    }
			    
			case -1068476919: // VIDIOC_QUERYBUF
			    {

			    len = 80;

			    let index = msg2.buf[24] | (msg2.buf[25] << 8) | (msg2.buf[26] << 16) |  (msg2.buf[27] << 24);

			    console.log("VIDIOC_QUERYBUF: index="+index);
			    
			    let offset = index * 4096;
			    
			    msg2.buf[24+64] = offset & 0xff;
			    msg2.buf[25+64] = (offset >> 8) & 0xff;
			    msg2.buf[26+64] = (offset >> 16) & 0xff;
			    msg2.buf[27+64] = (offset >> 24) & 0xff;
			    
			    let length = Module.video0.buffers[index].length;

			    msg2.buf[24+68] = length & 0xff;
			    msg2.buf[25+68] = (length >> 8) & 0xff;
			    msg2.buf[26+68] = (length >> 16) & 0xff;
			    msg2.buf[27+68] = (length >> 24) & 0xff;

			    break;

			    }
			    
			case -1068476913: // VIDIOC_QBUF

			    {
				
			    len = 80;

			    let index = msg2.buf[24] | (msg2.buf[25] << 8) | (msg2.buf[26] << 16) |  (msg2.buf[27] << 24);
			    
			    Module.video0.buffers[index].state = 1; // Enqueued
			    
				break;
			    }

			case 1074026002: // VIDIOC_STREAMON
			    {

				Module.video0.running = 1;

				Module.video0.play();

				if (!Module.video0.requestVideoFrameCallback) {
				    
				    let requestVideoFrameCallback = function (callback) {

					if (!this._rvfcpolyfillmap)
					    this._rvfcpolyfillmap = new Array();
					
					const handle = performance.now();

					const frameDuration = 1000.0 / this.mediaStream.getVideoTracks()[0].getSettings().frameRate;
					
					this._rvfcpolyfillmap[handle] = setTimeout(() => {

					    const now = performance.now();

					    callback(now, { 'presentationTime': now});
					    
					}, frameDuration);
					
					return handle;
				    };

				    Module.video0.requestVideoFrameCallback = requestVideoFrameCallback.bind(Module.video0);
				}

				Module.video0.requestVideoFrameCallback( Module.video0.drawingLoop );

				
				break;
			    }
			case -1068476911: // VIDIOC_DQBUF
			    {
				len = 80;

				let index = -1;
				
				for (let i=0; i < Module.video0.buffers.length; i+=1) {
				    
				    if (Module.video0.buffers[i].state == 2) {

					index = i;
					Module.video0.buffers[i].state = 0;

					if (Module.video0.buffers[i].ptr) {
					
					    const canvas = Module.video0.buffers[i].canvas;

					    const ctx = canvas.getContext("2d");

					    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

					    Module.HEAPU8.set(new Uint8Array(imageData.data.buffer), Module.video0.buffers[i].ptr);
					}
					
					break;
				    }
				}

				if (index >= 0) {

				    msg2.buf[24] = index & 0xff;
				    msg2.buf[25] = (index >> 8) & 0xff;
				    msg2.buf[26] = (index >> 16) & 0xff;
				    msg2.buf[27] = (index >> 24) & 0xff;
				}
				else {

				    _errno = EAGAIN;
				}
				
				break;
			    }
			    
			default:
			    
			    break;
			}
			
			if (!_errno) {
			    
			    if (len > 0)
				Module.HEAPU8.set(msg2.buf.slice(24, 24+len), argp);
			    
			    wakeUp(0);
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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
    $getSocketAddress__deps: ['$readSockaddr'],
    //, '$FS', '$DNS'],
  $getSocketAddress__docs: '/** @param {boolean=} allowNull */',
  $getSocketAddress: function(addrp, addrlen, allowNull) {
    if (allowNull && addrp === 0) return null;
      var info = readSockaddr(addrp, addrlen);
      if (info.errno) throw new FS.ErrnoError(info.errno);
      /* Modified by Benoit Baudaux 26/12/2022 */
      #if 0
      if (info.family != {{{ cDefine('AF_UNIX') }}} )
	  info.addr = DNS.lookup_addr(info.addr) || info.addr;
      #endif
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

	    let pid = Module.getpid();
	    
	    if (pid != 1) {

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		let buf = new Uint8Array(256);

		buf[0] = 9; // SOCKET
		
		/*//padding
		  buf[1] = 0;
		  buf[2] = 0;
		  buf[3] = 0;*/

		//let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (9|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (_errno == 0) {

			    let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			    let ops = null;
			    let remote_fd  = msg2.buf[28] | (msg2.buf[29] << 8) | (msg2.buf[30] << 16) |  (msg2.buf[31] << 24);

			    if (domain == 1) { // AF_UNIX

				ops = SOCKFS.unix_dgram_sock_ops;
			    }

			    // create our internal socket structure
			    let sock = {
				fd: fd,
				remote_fd: remote_fd,
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
				sock_ops: ops,
			    };

			    if (domain != 1) {

				sock.type = msg2.buf[32];
				sock.major = msg2.buf[34] | (msg2.buf[35] << 8);
				sock.minor = msg2.buf[36] | (msg2.buf[37] << 8);
				sock.peer = UTF8ArrayToString(msg2.buf, 38, 108);
			    }

			    Module['fd_table'][fd] = sock;

			    wakeUp(fd);
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

		/*if (!Module['fd_table']) {

		    Module['fd_table'] = {};
		    Module['fd_table'].last_fd = 0;
		}*/

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
    //TODO
    
    __syscall_getsockname__deps: ['$getSocketFromFD', '$writeSockaddr'],
    //, '$DNS'],
    __syscall_getsockname: function(fd, addr, addrlen) {

#if 0
    err("__syscall_getsockname " + fd);
    var sock = getSocketFromFD(fd);
    // TODO: sock.saddr should never be undefined, see TODO in websocket_sock_ops.getname
    var errno = writeSockaddr(addr, sock.family, /*DNS.lookup_name(sock.saddr || '0.0.0.0')*/'0.0.0.0', sock.sport, addrlen);
#if ASSERTIONS
    assert(!errno);
#endif
      return 0;

#endif

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    if (Module['fd_table'][fd].family == 1) {

		//TODO
	    }
	    else {

		let buf_size = 20+40;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 56; // GETSOCKNAME

		let pid = Module.getpid();

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

		// addrlen
		buf2.set(Module.HEAPU8.slice(addrlen, addrlen+4), 16);

		let len = Module.HEAPU8[addrlen] | (Module.HEAPU8[addrlen+1] << 8) | (Module.HEAPU8[addrlen+2] << 16) |  (Module.HEAPU8[addrlen+3] << 24);

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		  let msg2 = messageEvent.data;

		  if (msg2.buf[0] == (56|0x80)) {

		      let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		      if (!_errno) {

			  Module.HEAPU8.set(msg2.buf.slice(16, 16+4), addrlen);

			  let len2 = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			  if (len2 < len)
			      len = len2;
			  
			  Module.HEAPU8.set(msg2.buf.slice(20, 20+len), addr);
		      }

		      wakeUp(-_errno);

		      return hid;
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
		
	    }
	});

	return ret;
  },
    __syscall_getpeername__deps: ['$getSocketFromFD', '$writeSockaddr'],
    //, '$DNS'],
    __syscall_getpeername: function(fd, addr, addrlen) {

#if 0
    var sock = getSocketFromFD(fd);
    if (!sock.daddr) {
      return -{{{ cDefine('ENOTCONN') }}}; // The socket is not connected.
    }
      var errno = writeSockaddr(addr, sock.family, /*DNS.lookup_name(sock.daddr)*/'0.0.0.0', sock.dport, addrlen);
#if ASSERTIONS
    assert(!errno);
#endif
	return 0;

#endif

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    if (Module['fd_table'][fd].family == 1) {

		//TODO
	    }
	    else {

		let buf_size = 20+40;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 57; // GETPEERNAME

		let pid = Module.getpid();

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

		// addrlen
		buf2.set(Module.HEAPU8.slice(addrlen, addrlen+4), 16);

		let len = Module.HEAPU8[addrlen] | (Module.HEAPU8[addrlen+1] << 8) | (Module.HEAPU8[addrlen+2] << 16) |  (Module.HEAPU8[addrlen+3] << 24);

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		  let msg2 = messageEvent.data;

		  if (msg2.buf[0] == (57|0x80)) {

		      let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		      if (!_errno) {

			  Module.HEAPU8.set(msg2.buf.slice(16, 16+4), addrlen);

			  let len2 = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			  if (len2 < len)
			      len = len2;
			  
			  Module.HEAPU8.set(msg2.buf.slice(20, 20+len), addr);
		      }

		      wakeUp(-_errno);

		      return hid;
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
		
	    }
	});

	return ret;
  },
  __syscall_connect__deps: ['$getSocketFromFD', '$getSocketAddress'],
  __syscall_connect__sig: 'iipi',
  __syscall_connect: function(fd, addr, addrlen) {
    /*var sock = getSocketFromFD(fd);
    var info = getSocketAddress(addr, addrlen);
    sock.sock_ops.connect(sock, info.addr, info.port);
    return 0;*/

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  if (Module['fd_table'][fd].family == 1) {

	      //TODO
	  }
	  else {

	      let buf_size = 20+40;

	      let buf2 = new Uint8Array(buf_size);

	      buf2[0] = 55; // CONNECT

	      let pid = Module.getpid();

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

	      // addrlen
	      buf2[16] = addrlen & 0xff;
	      buf2[17] = (addrlen >> 8) & 0xff;
	      buf2[18] = (addrlen >> 16) & 0xff;
	      buf2[19] = (addrlen >> 24) & 0xff;

	      // addr
	      if (addr && addrlen > 0)
		  buf2.set(HEAPU8.slice(addr, addr+addrlen), 20);

	      const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		  let msg2 = messageEvent.data;

		  if (msg2.buf[0] == (55|0x80)) {

		      let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		      wakeUp(-_errno);

		      return hid;
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
	      
	  }
      });

      return ret;
  },
  __syscall_shutdown__deps: ['$getSocketFromFD'],
  __syscall_shutdown: function(fd, how) {
    getSocketFromFD(fd);
    return -{{{ cDefine('ENOSYS') }}}; // unsupported feature
  },
    __syscall_accept4__deps: ['$getSocketFromFD', '$writeSockaddr'],
    //, '$DNS'],
  __syscall_accept4: function(fd, addr, addrlen, flags) {
    var sock = getSocketFromFD(fd);
    var newsock = sock.sock_ops.accept(sock);
    if (addr) {
      var errno = writeSockaddr(addr, newsock.family, /*DNS.lookup_name(newsock.daddr)*/'0.0.0.0', newsock.dport, addrlen);
#if ASSERTIONS
      assert(!errno);
#endif
    }
    return newsock.stream.fd;
  },
  __syscall_bind__deps: ['$getSocketFromFD', '$getSocketAddress'],
  __syscall_bind__sig: 'iipi',
    __syscall_bind: function(fd, addr, addrlen) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    if (Module['fd_table'][fd].family == 1) {

		var sock = getSocketFromFD(fd);
		var info = getSocketAddress(addr, addrlen);

		sock.wakeUp = wakeUp;

		/* Modified by Benoit Baudaux 26/12/2022 */
		sock.sock_ops.bind(sock, info.addr, info.port);
		/*return 0;*/
		
	    }
	    else {

		let buf_size = 16+addrlen;
		
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 10; // BIND

		let pid = Module.getpid();

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
		
		// addr
		if (addr && addrlen > 0)
		    buf2.set(HEAPU8.slice(addr, addr+addrlen), 16);

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (10|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			wakeUp(-_errno);

			return hid;
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
	    }
	});
	    
	return ret;
  },
  __syscall_listen__deps: ['$getSocketFromFD'],
  __syscall_listen: function(fd, backlog) {
    var sock = getSocketFromFD(fd);
    sock.sock_ops.listen(sock, backlog);
    return 0;
  },
    __syscall_recvfrom__deps: ['$getSocketFromFD', '$writeSockaddr'],
//, '$DNS'],
    __syscall_recvfrom: function(fd, buf, len, flags, addr, addrlen) {
	/* Modified by Benoit Baudaux 26/12/2022 */
    /*var sock = getSocketFromFD(fd);
    var msg = sock.sock_ops.recvmsg(sock, len);
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

	    if (Module['fd_table'][fd].family == 1) {
		
		var sock = getSocketFromFD(fd);

		sock.wakeUp = wakeUp;

		sock.sock_ops.recvfrom(sock, buf, len, flags, addr, addrlen);
	    }
	    else {

		let buf_size = 24;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 54; // RECVFROM

		let pid = Module.getpid();
		
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

		// flags
		buf2[16] = flags & 0xff;
		buf2[17] = (flags >> 8) & 0xff;
		buf2[18] = (flags >> 16) & 0xff;
		buf2[19] = (flags >> 24) & 0xff;

		// len
		buf2[20] = len & 0xff;
		buf2[21] = (len >> 8) & 0xff;
		buf2[22] = (len >> 16) & 0xff;
		buf2[23] = (len >> 24) & 0xff;

		// addr_len
		buf2[24] = addrlen & 0xff;
		buf2[25] = (addrlen >> 8) & 0xff;
		buf2[26] = (addrlen >> 16) & 0xff;
		buf2[27] = (addrlen >> 24) & 0xff;

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (54|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let addrlen2 = msg2.buf[24] | (msg2.buf[25] << 8) | (msg2.buf[26] << 16) |  (msg2.buf[27] << 24);

			    if (addr && (addrlen2 > 0))
			    Module.HEAPU8.set(msg2.buf.slice(28, 28+addrlen2), addr);
			    let length = msg2.buf[20] | (msg2.buf[21] << 8) | (msg2.buf[22] << 16) |  (msg2.buf[23] << 24);
			    
			    if (buf && (length > 0))
				Module.HEAPU8.set(msg2.buf.slice(68, 68+length), buf);
			    
			    wakeUp(length);
			}
			else {
			    
			    wakeUp(-_errno);
			}
			
			return hid;
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
	    }
	});
	
	return ret;
  },
  __syscall_sendto__deps: ['$getSocketFromFD', '$getSocketAddress'],
  __syscall_sendto__sig: 'iipiipi',
    __syscall_sendto: function(fd, message, length, flags, addr, addr_len) {

	if (Module['fd_table'][fd].family == 1) {

	    var sock = getSocketFromFD(fd);
	    
	    var dest = getSocketAddress(addr, addr_len, true);
	    /* Modified by Benoit Baudaux 26/12/2022 */
	    /*if (!dest) {
	    // send, no address provided
	    return FS.write(sock.stream, {{{ heapAndOffset('HEAP8', 'message') }}}, length);
	    }
	    // sendto an address
	    return sock.sock_ops.sendmsg(sock, {{{ heapAndOffset('HEAP8', 'message') }}}, length, dest.addr, dest.port);*/

	    let uint8 = Module.HEAPU8.slice(message, message+length);
	    
	    return sock.sock_ops.sendto(sock, uint8, length, flags, dest.addr, dest.port);
	}
	else { // Send message to ip driver

	    let ret = Asyncify.handleSleep(function (wakeUp) {

		let buf_size = 28+40+length;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 52; // SENDTO

		let pid = Module.getpid();

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

		// flags
		buf2[16] = flags & 0xff;
		buf2[17] = (flags >> 8) & 0xff;
		buf2[18] = (flags >> 16) & 0xff;
		buf2[19] = (flags >> 24) & 0xff;

		// addr_len
		buf2[20] = addr_len & 0xff;
		buf2[21] = (addr_len >> 8) & 0xff;
		buf2[22] = (addr_len >> 16) & 0xff;
		buf2[23] = (addr_len >> 24) & 0xff;

		// addr
		if (addr && addr_len > 0)
		    buf2.set(Module.HEAPU8.slice(addr, addr+addr_len), 24);

		// length
		buf2[64] = length & 0xff;
		buf2[65] = (length >> 8) & 0xff;
		buf2[66] = (length >> 16) & 0xff;
		buf2[67] = (length >> 24) & 0xff;

		// message
		if (message && length > 0)
		    buf2.set(Module.HEAPU8.slice(message, message+length), 68);

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (52|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno)
			    wakeUp(length);
			else
			    wakeUp(-_errno);

			return hid;
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
	    
	}
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
    __syscall_sendmsg__deps: ['$getSocketFromFD', '$readSockaddr'],
			      //, '$DNS'],
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
      addr = /*DNS.lookup_addr(info.addr) ||*/ info.addr;
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
    __syscall_recvmsg__deps: ['$getSocketFromFD', '$writeSockaddr'],
    //, '$DNS'],
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
      var errno = writeSockaddr(name, sock.family, /*DNS.lookup_name(msg.addr)*/'0.0.0.0', msg.port);
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
    /*var nonzero = 0;
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
    return nonzero;*/

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  let readfds_array = [];
	  let writefds_array = [];
	  
	  for (let i=0; i < nfds; i++) {

	      let fd = Module.HEAPU8[fds+i*8] | (Module.HEAPU8[fds+i*8+1] << 8) | (Module.HEAPU8[fds+i*8+2] << 16) |  (Module.HEAPU8[fds+i*8+3] << 24);

	      if (fd >= 0) {

		  let events = Module.HEAPU8[fds+i*8+4] | (Module.HEAPU8[fds+i*8+5] << 8);

		  if ((events & 0x01) == 0x01)  // POLLIN
		      readfds_array.push(fd);

		  if ((events & 0x04) == 0x04)  //POLLOUT
		      writefds_array.push(fd);

		  Module.HEAPU8[fds+i*8+6] = 0;
		  Module.HEAPU8[fds+i*8+7] = 0;
	      }
	  }

	  let do_select = (fd, rw, start) => {

	      let buf_size = 256;
	      
	      let buf2 = new Uint8Array(buf_size);

	      buf2[0] = 31; // SELECT

	      let pid = Module.getpid();

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

	      // once
	      buf2[28] = (timeout == 0);
	      buf2[29] = 0;
	      buf2[30] = 0;
	      buf2[31] = 0;

	      if (Module['fd_table'][fd].timerfd) { // timerfd

		  Module['fd_table'][fd].select(fd, rw, start, function(_fd, rw) {

		      //console.log("timerfd notif_select _fd="+_fd);
		      
		      notif_select(_fd, rw);
		  });
	      }
	      else if (Module['fd_table'][fd].sock_ops) { // socket

		  Module['fd_table'][fd].sock_ops.select(getSocketFromFD(fd), fd, rw, start, function(_fd, rw) {

		      //console.log("sock notif_select _fd="+_fd);

		      notif_select(_fd, rw);
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

	      //console.log("notify_select: fd="+fd);

	      if (Module['select_timer'])
		  clearTimeout(Module['select_timer']);
	      
	      // Stop select for readfds if not once

	      if (timeout != 0) {
	      
		  for (let readfd of readfds_array) {

		      if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

			  do_select(readfd, 0, 0);
		      }
		  }

		  // Stop select for writefds

		  for (let writefd of writefds_array) {

		      if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

			  do_select(writefd, 1, 0);
		      }
		  }
	      }
	      
	      if (fd >= 0) {

		  for (let i=0; i < nfds; i++) {

		      let fd2 = Module.HEAPU8[fds+i*8] | (Module.HEAPU8[fds+i*8+1] << 8) | (Module.HEAPU8[fds+i*8+2] << 16) |  (Module.HEAPU8[fds+i*8+3] << 24);

		      if (fd == fd2) {

			  if (rw)
			      Module.HEAPU8[fds+i*8+6] = 4; //POLLOUT
			  else
			      Module.HEAPU8[fds+i*8+6] = 1; //POLLIN
			  
			  Module.HEAPU8[fds+i*8+7] = 0;
		      }
		  }

		  wakeUp(1);
	      }
	      else {

		  wakeUp(0);
	      }
	  };
	  
	  let selectfds_array = [].concat(readfds_array, writefds_array);

	  let check_unknown_fds = (fds, callback) => {

	      if (fds.length == 0) {
		  callback();
		  return;
	      }

	      let fd = fds.pop();

	      if ( !(fd in Module['fd_table']) || !Module['fd_table'][fd] ) {

		  let buf_size = 256;

		  let buf2 = new Uint8Array(buf_size);

		  buf2[0] = 26; // IS_OPEN

		  let pid = Module.getpid();

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

		  const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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
			  }

			  check_unknown_fds(fds, callback);
			  
			  return hid;
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
	      else {
		  check_unknown_fds(fds, callback);
	      }
	  }

	  check_unknown_fds(selectfds_array, () => {

	      const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		  let msg2 = messageEvent.data;
		  
		  if (msg2.buf[0] == (31|0x80)) {

		      let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

		      let rw = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		      notif_select(fd, rw);

		      return hid;
		  }
		  else if (msg2.buf[0] == 62) { // END_OF_SIGNAL Signal received and handled
		      
		      //console.log("Signal has interrupted poll  syscall");
		      
		      //TODO: check flags
		      
		      wakeUp(-4); //EINTR

		      return hid;
		    }
		  else {

		      return -1;
		  }
	      });

	      let i = 0;

	      // Start select for readfds
	      
	      for (let readfd of readfds_array) {

		  if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

		      i++;
		      do_select(readfd, 0, 1);
		  }
	      }
	      
	      // Start select for writefds

	      for (let writefd of writefds_array) {

		  if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

		      i++;
		      do_select(writefd, 1, 1);
		  }
	      }

	      if (i == 0) { // no fd for select

		  wakeUp(0);
	      }
	      else if (timeout >= 0) {

		  Module['select_timer'] = setTimeout(() => {

		      Module['rcv_bc_channel'].unset_handler(hid);
		      
		      notif_select(-1, -1);
		      
		  }, (timeout == 0)?5:timeout);
	      }
	  });
	  
      });

      return ret;
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

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			wakeUp(-_errno);
		    }

		    return hid;
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
  __syscall_truncate64__sig: 'ipi',
  //__syscall_truncate64__deps: i53ConversionDeps,
    __syscall_truncate64: function(path, length) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 1256;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 63; // TRUNCATE
	    
	    /*//padding
	      buf[1] = 0;
	      buf[2] = 0;
	      buf[3] = 0;*/

	    let pid = Module.getpid();

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

	    buf2[12] = length & 0xff;
	    buf2[13] = (length >> 8) & 0xff;
	    buf2[14] = (length >> 16) & 0xff;
	    buf2[15] = (length >> 24) & 0xff;

	    let path_len = 0;

	    while (Module.HEAPU8[path+path_len]) {

		path_len++;
	    }

	    path_len++;

	    buf2[16] = path_len & 0xff;
	    buf2[17] = (path_len >> 8) & 0xff;
	    buf2[18] = (path_len >> 16) & 0xff;
	    buf2[19] = (path_len >> 24) & 0xff;

	    buf2.set(Module.HEAPU8.slice(path, path+path_len), 20);
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (63|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);
		    
		    wakeUp(-_errno);
		    
		    return hid;
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
      

      /* Modified by Benoit Baudaux 2/10/2023 */
      
    /*path = SYSCALLS.getStr(path);
    FS.truncate(path, length);
    return 0;*/
  },
  __syscall_ftruncate64__sig: 'iii',
  //__syscall_ftruncate64__deps: i53ConversionDeps,
    __syscall_ftruncate64: function(fd, length) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    /* Modified by Benoit Baudaux 2/10/2023 */	
	    
	    if (fd >= 0x7f000000) { // Shm

		//console.log("__syscall_ftruncate64: shm length="+length);

		Module['shm'].fds[fd-0x7f000000].size = length;

		wakeUp(0);
		
		return;
	    }

	    //console.log("__syscall_lseek: off="+offset+", whence="+whence);

	    let do_ftrunc = () => {

		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 64; // FTRUNCATE

		let pid = Module.getpid();

		// pid
		buf2[4] = pid & 0xff;
		buf2[5] = (pid >> 8) & 0xff;
		buf2[6] = (pid >> 16) & 0xff;
		buf2[7] = (pid >> 24) & 0xff;

		let remote_fd = Module['fd_table'][fd].remote_fd;

		// length
		buf2[12] = length & 0xff;
		buf2[13] = (length >> 8) & 0xff;
		buf2[14] = (length >> 16) & 0xff;
		buf2[15] = (length >> 24) & 0xff;

		// fd
		buf2[16] = remote_fd & 0xff;
		buf2[17] = (remote_fd >> 8) & 0xff;
		buf2[18] = (remote_fd >> 16) & 0xff;
		buf2[19] = (remote_fd >> 24) & 0xff;

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (64|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			//console.log("bytes_read: "+bytes_read);

			wakeUp(-_errno);

			return hid;
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

		do_ftrunc();
	    }
	    else {
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    do_ftrunc();

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

#if 0
    FS.ftruncate(fd, length);
	return 0;
#endif
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

	    let pid = Module.getpid();

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
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (28|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);
		    
		    if (_errno == 0) {

			let len = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			//console.log("__syscall_stat64: len="+len);

			Module.HEAPU8.set(msg2.buf.slice(16, 16+len), buf);

			wakeUp(0);
		    }
		    else {

			wakeUp(-_errno);
		    }

		    return hid;
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

	    let pid = Module.getpid();

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
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			wakeUp(-_errno);
		    }

		    return hid;
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
		
		let pid = Module.getpid();
		
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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    wakeUp(-_errno);
			}

			return hid;
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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    return -1; // Do not reset handler as it is set by do_fstat
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

	    let pid = Module.getpid();

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

	    //TODO check if fd is in the table
	    
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
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			wakeUp(-_errno);
		    }

		    return hid;
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
  //__syscall_fcntl64__deps: ['$setErrNo'],
  __syscall_fcntl64__sig: 'iiip',
  __syscall_fcntl64: function(fd, cmd, varargs) {
#if SYSCALLS_REQUIRE_FILESYSTEM == 0
#if SYSCALL_DEBUG
    dbg('no-op in fcntl syscall due to SYSCALLS_REQUIRE_FILESYSTEM=0');
#endif
    return 0;
#else

      //console.log("__syscall_fcntl: varargs="+varargs);

      var argp = SYSCALLS.get();

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  let buf_size = 256;

	  let buf2 = new Uint8Array(buf_size);

	  buf2[0] = 17; // FCNTL

	  let pid = Module.getpid();

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

	  //cmd
	  buf2[16] = cmd & 0xff;
	  buf2[17] = (cmd >> 8) & 0xff;
	  buf2[18] = (cmd >> 16) & 0xff;
	  buf2[19] = (cmd >> 24) & 0xff;

	  if ( (cmd == {{{ cDefine('F_SETFD') }}}) ||
	       (cmd == {{{ cDefine('F_DUPFD') }}}) ||
	       (cmd == {{{ cDefine('F_DUPFD_CLOEXEC') }}}) ||
	       (cmd == {{{ cDefine('F_SETFL') }}}) ) {
	      
	      len = 4; // arg is an int
	  }
	  else {
	      len = 0;
	  }

	  buf2[24] = len & 0xff;
	  buf2[25] = (len >> 8) & 0xff;
	  buf2[26] = (len >> 16) & 0xff;
	  buf2[27] = (len >> 24) & 0xff;

	  if (len == 4) {

	      buf2[28] = argp & 0xff;
	      buf2[29] = (argp >> 8) & 0xff;
	      buf2[30] = (argp >> 16) & 0xff;
	      buf2[31] = (argp >> 24) & 0xff;
	  }
	  else if (len > 4) {

	      buf2.set(Module.HEAPU8.slice(argp, argp+len), 28);
	  }
	  
	  const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

	      let msg2 = messageEvent.data;

	      if (msg2.buf[0] == (17|0x80)) {

		  //console.log("<-- __syscall_fcntl64");

		  let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		  if (!_errno) {

		      let _ret = msg2.buf[20] | (msg2.buf[21] << 8) | (msg2.buf[22] << 16) |  (msg2.buf[23] << 24);

		      wakeUp(_ret);
		  }
		  else {
		  
		      wakeUp(-_errno);
		  }

		  return hid;
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
      });
    
    return ret;

      /* Modified by Benoit Baudaux 17/1/2023 */

      #if 0
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

#endif
      
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

	//if (Module.getpid() == 12)
	//    debugger;

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    if (UTF8ArrayToString(Module.HEAPU8, path, 9) == "/dev/shm/") {

		let path_len = 0;

		while (Module.HEAPU8[path+path_len]) {

		    path_len++;
		}

		path_str = UTF8ArrayToString(Module.HEAPU8, path, path_len);

		//console.log("library_syscall: openat /dev/shm "+path_str);
		
		if (!Module['shm']) {
		    Module['shm'] = {};
		    Module['shm'].names = {};
		    Module['shm'].fds = new Array(16);

		    for (let i = 0; i < 16; i += 1) {

			Module['shm'].fds[i] = {};
			Module['shm'].fds[i].name = "";
		    }
		}

		let i = 0;

		for (; i < 16; i += 1) {

		    if (Module['shm'].fds[i].name == "") {
			Module['shm'].fds[i].name = path_str;
			Module['shm'].names[path_str] = i;

			wakeUp(0x7f000000+i);
			return -1;
		    }
		}

		wakeUp(-1);
		return -1;
	    }

	    let pid = Module.getpid();
	    
	    if (pid != 1) {

		var mode = varargs ? SYSCALLS.get() : 0;

		//console.log("__syscall_openat: pid="+pid+", mode="+mode);

		//if (pid == 12)
		//    debugger;

		let bc = Module.get_broadcast_channel("/var/resmgr.peer");

		let buf_size = 1256;
	
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 11; // OPEN

		/*//padding
		  buf[1] = 0;
		  buf[2] = 0;
		  buf[3] = 0;*/

		//let pid = Module.getpid();

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

		buf2.set(Module.HEAPU8.slice(path, path+path_len), 140);
		
		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    //console.log(messageEvent);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (11|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			//console.log("__syscall_openat: _errno=%d", _errno);
			
			    if (_errno == 0) {

				let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);
				let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
				let flags = msg2.buf[20] | (msg2.buf[21] << 8) | (msg2.buf[22] << 16) |  (msg2.buf[23] << 24);
				let mode = msg2.buf[24] | (msg2.buf[25] << 8);
				let type = msg2.buf[26];
				let major = msg2.buf[28] | (msg2.buf[29] << 8);
				let minor = msg2.buf[30] | (msg2.buf[31] << 8);
				let peer = UTF8ArrayToString(msg2.buf, 32, 108);

				//console.log("__syscall_openat: peer=%s fd=%d", peer, fd);

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

				if (peer == "/var/fb.peer") { // fb has been opened successfully
				    
				    let m = {
	    
					type: 5,   // show iframe
					pid: pid & 0x0000ffff
				    };

				    window.parent.postMessage(m);

				    document.body.style.margin = 0;
				    document.body.style.border = 0;
				    document.body.style.width = "100vw";
				    document.body.style.height = "100vh";

				    const canvas = document.createElement("canvas");
				    
				    document.body.appendChild(canvas);

				    const ctx = canvas.getContext('2d');

				    const scale = window.devicePixelRatio;

				    const w = Math.floor(/*window.innerWidth*/800 * scale);
				    const h = Math.floor(/*window.innerHeight*/600 * scale);
				    
				    const width = Math.floor((w+3)/4)*4;
				    const height = Math.floor((h+3)/4)*4;
				    
				    canvas.width = width;
				    canvas.height = height;

				    canvas.style.width = "100%";
				    canvas.style.height = "100%";
				    
				    ctx.scale(scale, scale);

				    const fb_size = width * height * 4;

				    const fb = Module._malloc(fb_size);

				    const pixels = new Uint8ClampedArray(Module.HEAPU8.buffer, fb, fb_size);

				    const imageData = new ImageData(pixels, width, height);

				    Module['fd_table'][fd].ctx = ctx;
				    Module['fd_table'][fd].fb = fb;
				    Module['fd_table'][fd].pixels = pixels;
				    Module['fd_table'][fd].imageData = imageData;

				    let nb_frames = 0;
				    let start = Date.now();
				    
				    let render = function() {

					nb_frames++;

					
					if (nb_frames%200 == 0) {

					    fps = 1000.0*nb_frames/(Date.now()-start);

					    //console.log(fps.toFixed(2).toString() + " fps");

					    nb_frames = 0;
					    start = Date.now();
					}

					ctx.putImageData(imageData, 0, 0);

					window.requestAnimationFrame(render);
				    }

				    window.requestAnimationFrame(render);

				    wakeUp(fd);
				}
				else if (UTF8ArrayToString(Module.HEAPU8, path, 11) == "/dev/video0") {
				    var constraints = { audio: false, video: true };
				    navigator.mediaDevices
					.getUserMedia(constraints)
					.then(function (mediaStream) {

					    console.log("/dev/video0 opened");
					    console.log(mediaStream);
					    console.log(mediaStream.getVideoTracks()[0].getSettings());

					    Module.video0 = document.createElement("video");
					    Module.video0.mediaStream = mediaStream;
					    
					    if ("srcObject" in Module.video0) {
						Module.video0.srcObject = mediaStream;
					    } else {
						// Avoid using this in new browsers, as it is going away.
						Module.video0.src = URL.createObjectURL(mediaStream);
					    }

					    Module.video0.running = 0;
					    
					    Module.video0.drawingLoop = (timestamp, frame) => {

						if (Module.video0.running) {

						    for (let buffer of Module.video0.buffers) {

							if (buffer.state == 1) {

							    const ctx = buffer.canvas.getContext("2d");
							    ctx.drawImage(Module.video0, 0, 0 );

							    buffer.state = 2;
							    buffer.presentationTime = frame.presentationTime;

							    //console.log("Frame captured "+timestamp);

							    
							    //console.log(frame);

							    if (Module.video0.notif_select)
								Module.video0.notif_select(Module.video0.select_fd, Module.video0.select_rw);
							    
							    break;
							}
						    }
						
						    //console.log(timestamp);
						    //console.log(frame);

						    //this.ctx1.drawImage(this.video, 0, 0, this.width, this.height);
						    //const frame = this.ctx1.getImageData(0, 0, this.width, this.height);
						    
						    Module.video0.requestVideoFrameCallback( Module.video0.drawingLoop );
						}
					    };

					    Module['fd_table'][fd].select = function (fd, rw, start_stop, notif_select) {

						if (start_stop) {

						    for (let buffer of Module.video0.buffers) {

							if (buffer.state == 2) {

							    Module.video0.notif_select = null;
							    notif_select(fd, rw);
							    
							    return;
							}
						    }

						    Module.video0.select_fd = fd;
						    Module.video0.select_rw = rw;
						    Module.video0.notif_select = notif_select;
						}
						else {

						    Module.video0.notif_select = null;
						}
					    };
						

					    //document.body.appendChild(Module.video0);

					    wakeUp(fd);
					})
					.catch(function (err) {
					    console.log(err.name + ": " + err.message);
					    //TODO: close fd

					    wakeUp(-1);
					    
					}); // always check for errors at the end.
				    
				}
				else {

				    wakeUp(fd);
				}
			    }
			    else {

				wakeUp(-_errno);
			    }

			return hid;
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

      /* Modified by Benoit Baudaux 24/01/2024*/

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  let buf_size = 1256;
	  
	  let buf2 = new Uint8Array(buf_size);
	  
	  buf2[0] = 65; // MKDIRAT
	  
	  let pid = Module.getpid();
	  
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

	  buf2[12] = dirfd & 0xff;
	  buf2[13] = (dirfd >> 8) & 0xff;
	  buf2[14] = (dirfd >> 16) & 0xff;
	  buf2[15] = (dirfd >> 24) & 0xff;

	  buf2[16] = mode & 0xff;
	  buf2[17] = (mode >> 8) & 0xff;
	  buf2[18] = (mode >> 16) & 0xff;
	  buf2[19] = (mode >> 24) & 0xff;

	  let path_len = 0;

	  while (Module.HEAPU8[path+path_len]) {

	      path_len++;
	  }

	  path_len++;

	  buf2[20] = path_len & 0xff;
	  buf2[21] = (path_len >> 8) & 0xff;
	  buf2[22] = (path_len >> 16) & 0xff;
	  buf2[23] = (path_len >> 24) & 0xff;

	  buf2.set(Module.HEAPU8.slice(path, path+path_len), 24);
	  
	  const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

	      let msg2 = messageEvent.data;

	      if (msg2.buf[0] == (65|0x80)) {

		  let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		  wakeUp(-_errno);

		  return hid;
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
      

#if 0
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
#endif
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
    /*path = SYSCALLS.getStr(path);
    path = SYSCALLS.calculateAt(dirfd, path);
    if (flags === 0) {
      FS.unlink(path);
    } else if (flags === {{{ cDefine('AT_REMOVEDIR') }}}) {
      FS.rmdir(path);
    } else {
      abort('Invalid flags passed to unlinkat');
    }
    return 0;*/

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  let buf_size = 1256;
	  
	  let buf2 = new Uint8Array(buf_size);
	  
	  buf2[0] = 50; // UNLINKAT
	  
	  let pid = Module.getpid();
	  
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

	  buf2[12] = dirfd & 0xff;
	  buf2[13] = (dirfd >> 8) & 0xff;
	  buf2[14] = (dirfd >> 16) & 0xff;
	  buf2[15] = (dirfd >> 24) & 0xff;
	  
	  buf2[16] = flags & 0xff;
	  buf2[17] = (flags >> 8) & 0xff;
	  buf2[18] = (flags >> 16) & 0xff;
	  buf2[19] = (flags >> 24) & 0xff;

	  let path_len = 0;

	  while (Module.HEAPU8[path+path_len]) {

	      path_len++;
	  }

	  path_len++;

	  buf2[20] = path_len & 0xff;
	  buf2[21] = (path_len >> 8) & 0xff;
	  buf2[22] = (path_len >> 16) & 0xff;
	  buf2[23] = (path_len >> 24) & 0xff;

	  buf2.set(Module.HEAPU8.slice(path, path+path_len), 24);
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (50|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_stat64: _errno="+_errno);
		    
		    wakeUp(-_errno);

		    return hid;
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
  __syscall_renameat__sig: 'iipip',
  __syscall_renameat: function(olddirfd, oldpath, newdirfd, newpath) {
	
    /*oldpath = SYSCALLS.getStr(oldpath);
    newpath = SYSCALLS.getStr(newpath);
    oldpath = SYSCALLS.calculateAt(olddirfd, oldpath);
    newpath = SYSCALLS.calculateAt(newdirfd, newpath);
    FS.rename(oldpath, newpath);
    return 0;*/

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  let buf_size = 2084;
	  
	  let buf2 = new Uint8Array(buf_size);
	  
	  buf2[0] = 51; // RENAMEAT
	  
	  let pid = Module.getpid();
	  
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

	  buf2[12] = olddirfd & 0xff;
	  buf2[13] = (olddirfd >> 8) & 0xff;
	  buf2[14] = (olddirfd >> 16) & 0xff;
	  buf2[15] = (olddirfd >> 24) & 0xff;

	  let path_len = 0;

	  while (Module.HEAPU8[oldpath+path_len]) {

	      path_len++;
	  }

	  path_len++;

	  buf2[16] = path_len & 0xff;
	  buf2[17] = (path_len >> 8) & 0xff;
	  buf2[18] = (path_len >> 16) & 0xff;
	  buf2[19] = (path_len >> 24) & 0xff;

	  buf2.set(Module.HEAPU8.slice(oldpath, oldpath+path_len), 20);

	  buf2[20+1024] = newdirfd & 0xff;
	  buf2[21+1024] = (newdirfd >> 8) & 0xff;
	  buf2[22+1024] = (newdirfd >> 16) & 0xff;
	  buf2[23+1024] = (newdirfd >> 24) & 0xff;

	  path_len = 0;

	  while (Module.HEAPU8[newpath+path_len]) {

	      path_len++;
	  }

	  path_len++;

	  buf2[24+1024] = path_len & 0xff;
	  buf2[25+1024] = (path_len >> 8) & 0xff;
	  buf2[26+1024] = (path_len >> 16) & 0xff;
	  buf2[27+1024] = (path_len >> 24) & 0xff;

	  buf2.set(Module.HEAPU8.slice(newpath, newpath+path_len), 28+1024);
	    
	  const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

	      let msg2 = messageEvent.data;

	      if (msg2.buf[0] == (51|0x80)) {

		  let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		  wakeUp(-_errno);

		  return hid;
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

      let ret = Asyncify.handleSleep(function (wakeUp) {

	  let buf_size = 1256;
	  
	  let buf2 = new Uint8Array(buf_size);
	  
	  buf2[0] = 46; // FACCESSAT
	  
	  let pid = Module.getpid();
	  
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

	  buf2[12] = dirfd & 0xff;
	  buf2[13] = (dirfd >> 8) & 0xff;
	  buf2[14] = (dirfd >> 16) & 0xff;
	  buf2[15] = (dirfd >> 24) & 0xff;

	  buf2[16] = amode & 0xff;
	  buf2[17] = (amode >> 8) & 0xff;
	  buf2[18] = (amode >> 16) & 0xff;
	  buf2[19] = (amode >> 24) & 0xff;

	  buf2[20] = flags & 0xff;
	  buf2[21] = (flags >> 8) & 0xff;
	  buf2[22] = (flags >> 16) & 0xff;
	  buf2[23] = (flags >> 24) & 0xff;

	    let path_len = 0;

	    while (Module.HEAPU8[path+path_len]) {

		path_len++;
	    }

	    path_len++;

	    buf2[24] = path_len & 0xff;
	    buf2[25] = (path_len >> 8) & 0xff;
	    buf2[26] = (path_len >> 16) & 0xff;
	    buf2[27] = (path_len >> 24) & 0xff;

	    buf2.set(Module.HEAPU8.slice(path, path+path_len), 28);
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		//console.log(messageEvent);

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (46|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    //console.log("__syscall_stat64: _errno="+_errno);

		    wakeUp(-_errno);

		    return hid;
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

/* Modified by Benoit Baudaux 5/5/2023 */
#if 0
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
#endif
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

	    let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		    
		    //console.log(messageEvent);

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (7|0x80)) {

			Module.child_pid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			do_fork();

			return hid;
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
		
		//console.log("do_exec: "+path);
		
		let buf_size = 1256;

		let buf = new Uint8Array(buf_size);

		buf[0] = 8; // EXECVE

		let pid = Module.getpid();

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

		let rcv_bc = Module['rcv_bc_channel'] || new BroadcastChannel("channel.process."+Module.getpid());

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
		
		if ( (path.indexOf("/bin") === 0) || ( (path.indexOf("/usr") === 0) && ((path.indexOf("/usr/share/bin") !== 0)) ) ) {
		    window.frameElement.src = "/netfs" + path+"/exa/exa.html";
		}
		else {
		    window.frameElement.setAttribute("path", path);
		    window.frameElement.src = "/exa/process.html";
		}
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

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			//console.log("cwd:"+cwd);
			
			do_exec(cwd+sep+path);
		    }
		    else {

			wakeUp(-_errno);
		    }

		    return hid;
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

		let pid = Module.getpid();
		
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

		if (buf && len > 0)
		    buf2.set(HEAPU8.slice(buf, buf+len), 20);

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (13|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {
			
			let bytes_written = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			
			    wakeUp(bytes_written);
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

		if (iov && (iovcnt > 0)) {
		    
		    let iov2 = iov;

		    for (var i = 0; i < iovcnt; i++) {
			len += {{{ makeGetValue('iov2', C_STRUCTS.iovec.iov_len, '*') }}};
			iov2 += {{{ C_STRUCTS.iovec.__size__ }}};
		    }
		}

		let buf_size = 20+len;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 13; // WRITE
		
		let pid = Module.getpid();

		//console.log("writev: tid="+pid);

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

		if (iov && (iovcnt > 0)) {
		    
		    let iov2 = iov;

		    for (var i = 0; i < iovcnt; i++) {
			
			let ptr = {{{ makeGetValue('iov2', C_STRUCTS.iovec.iov_base, '*') }}};
			if (ptr) {
			    let l = {{{ makeGetValue('iov2', C_STRUCTS.iovec.iov_len, '*') }}};
			    
			    if (l > 0)
				buf2.set(HEAPU8.slice(ptr, ptr+l), buf_size);
			    
			    buf_size += l;
			}

			iov2 += {{{ C_STRUCTS.iovec.__size__ }}};
		    }
		}

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (13|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let bytes_written = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
			    
			    wakeUp(bytes_written);
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

	return Module.getpid() & 0xffff;
    },
    /* Modified by Benoit Baudaux 11/1/2023 */
    __syscall_close__sig: 'ii',
    __syscall_close: function(fd) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_close = () => {

		let buf_size = 16;
		
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 15; // CLOSE

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (15|0x80)) {

			//console.log(messageEvent);
			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {
			    
			    if (Module['fd_table'][fd].peer == "/var/fb.peer") { // fb has been opened successfully
				    
				let m = {
				    
				    type: 6,   // hide iframe
				    pid: pid
				};

				const canvas = document.getElementsByTagName("canvas")[0];
				    
				document.body.removeChild(canvas);
			    }

			    Module['fd_table'][fd] = null;
			}

			wakeUp(-_errno);

			return hid;
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
	    };

	    if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) ) {

		if (Module['fd_table'][fd].timerfd && Module['fd_table'][fd].timeout_id) {

		    clearTimeout(Module['fd_table'][fd].timeout_id);
		}

		let pid = Module.getpid();

		if (pid > 1) {
		    do_close();
		}
		else {
		    Module['fd_table'][fd] = null;
		    wakeUp(0);
		}
	    }
	    else {
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    do_close();

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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
    /* Modified by Benoit Baudaux 13/1/2023 */
    __syscall_setsid__sig: 'i',
    __syscall_setsid: function() {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 16;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 16; // SETSID

	    let pid = Module.getpid();

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

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (16|0x80)) {

		    //console.log(messageEvent);

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    if (!_errno) {

			let sid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);
			
			Module['sid'] = sid;

			wakeUp(sid);
		    }
		    else {

			wakeUp(-_errno);
		    }

		    return hid;
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

	    let pid = Module.getpid();

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

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (18|0x80)) {

		    //console.log(messageEvent);
		    
		    let sid = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    wakeUp(sid);

		    return hid;
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

	//console.log("__syscall_read: fd="+fd+", count="+count);

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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (12|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let bytes_read = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			    //console.log("__syscall_read: bytes_read="+bytes_read);

			    if (bytes_read > 0)
				Module.HEAPU8.set(msg2.buf.slice(20, 20+bytes_read), buf);
			    
			    wakeUp(bytes_read);
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
		    }
		    else if (msg2.buf[0] == 62) { // END_OF_SIGNAL Signal received and handled

			//TODO: check flags
			
			wakeUp(-4); //EINTR
			
			return hid;
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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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

	    //console.log("__syscall_readv: iovcnt="+iovcnt+", count="+count);

	    let do_readv = () => {

		let len = count;
		
		let buf_size = 20;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 12; // READ

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    //console.log("__syscall_readv handler "+msg2.buf[0]);

		    if (msg2.buf[0] == (12|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			if (!_errno) {

			    let bytes_read = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			    //console.log("__syscall_readv: bytes_read="+bytes_read);

			    /*for (let i=0;i<bytes_read; i+= 160) {
			      
			      console.log("* "+i+": "+msg2.buf[20+i]+" "+msg2.buf[20+i+1]+" "+msg2.buf[20+i+2]+" "+msg2.buf[20+i+3]);
			      }*/

			    let offset = 0;

			    for (let i = 0; i < iovcnt; i++) {

				let len =  Module.HEAPU8[iov+8*i+4] | (Module.HEAPU8[iov+8*i+5] << 8) | (Module.HEAPU8[iov+8*i+6] << 16) |  (Module.HEAPU8[iov+8*i+7] << 24);

				//console.log("__syscall_readv: "+i+", len="+len);
				
				let len2 = ((offset+len) <= bytes_read)?len:bytes_read-offset;

				//console.log("__syscall_readv: "+i+", len2="+len2);

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
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
		    }
		    else if (msg2.buf[0] == 62) { // END_OF_SIGNAL Signal received and handled

			//TODO: check flags
			
			wakeUp(-4); //EINTR

			return hid;
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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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
	    //console.log("__syscall_pause");
	});
	
	return ret;
    },
    __syscall_getpgid__sig: 'ii',
    __syscall_getpgid: function(req_pid) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 20;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 21; // GETPGID

	    let pid = Module.getpid();

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

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (21|0x80)) {

		    //console.log(messageEvent);
		    
		    let pgid = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    wakeUp(pgid);

		    return hid;
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

	    let pid = Module.getpid();

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

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (22|0x80)) {

		    //console.log(messageEvent);
		    
		    wakeUp(0);

		    return hid;
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

	    let pid = Module.getpid();

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

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (20|0x80)) {

		    //console.log(messageEvent);
		    
		    let ppid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

		    wakeUp(ppid);

		    return hid;
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

	    let pid = Module.getpid();

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
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (27|0x80)) {

		    //console.log(messageEvent);
		    
		    // TODO: check bufsize

		    let len = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

		    Module.HEAPU8.set(msg2.buf.slice(20, 20+len), buf);

		    wakeUp(len-1); // Remove last zero frol len

		    return hid;
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
	
	//console.log("__syscall_pselect6: s="+s+", ns="+ns);
	//console.log(Module['fd_table']);

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    //console.log("__syscall_pselect6: nfds="+nfds);

	    let s = -1;
	    let ns = 0;

	    if (timeout) {

		s = Module.HEAPU8[timeout] | (Module.HEAPU8[timeout+1] << 8) | (Module.HEAPU8[timeout+2] << 16) |  (Module.HEAPU8[timeout+3] << 24);

		ns = Module.HEAPU8[timeout+4] | (Module.HEAPU8[timeout+5] << 8) | (Module.HEAPU8[timeout+6] << 16) |  (Module.HEAPU8[timeout+7] << 24);

		//end = 1000*s + 1000000*ns;

		//console.log("__syscall_pselect6: timeout s="+s+", ns="+ns);
	    }

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

		let pid = Module.getpid();

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

		// once
		buf2[28] = (s == 0) && (ns == 0);
		buf2[29] = 0;
		buf2[30] = 0;
		buf2[31] = 0;

		if (Module['fd_table'][fd].timerfd) { // timerfd

		    Module['fd_table'][fd].select(fd, rw, start, function(_fd, rw) {
			//console.log("timerfd notif_select _fd="+_fd);
			
			notif_select(_fd, rw);
		    });
		}
		else if (Module['fd_table'][fd].sock_ops) { // socket

		    Module['fd_table'][fd].sock_ops.select(getSocketFromFD(fd), fd, rw, start, function(_fd, rw) {

			//console.log("sock notif_select _fd="+_fd);

			notif_select(_fd, rw);
		    });
		}
		else if (Module['fd_table'][fd].select) { // TODO: to be generalize 

		    Module['fd_table'][fd].select(fd, rw, start, function(_fd, rw) {
			//console.log("timerfd notif_select _fd="+_fd);
			
			notif_select(_fd, rw);
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

		    //console.log("__syscall_pselect6: peer="+Module['fd_table'][fd].peer);

		    let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		    
		    driver_bc.postMessage(msg);
		}
	    };

	    let notif_select = (fd, rw) => {

		//console.log("__syscall_pselect6: notify_select: fd="+fd+", nfds="+nfds);

		/* Workaround before implement id in syscall */
		if ( (fd != -1) && ((rw && !writefds_array.includes(fd)) || (!rw && !readfds_array.includes(fd)) ) )
		    return;

		if (Module['select_timer'])
		    clearTimeout(Module['select_timer']);
		
		// Stop select for readfds if not once

		if (!((s == 0) && (ns == 0))) {
		
		    for (let readfd of readfds_array) {

			if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

			    do_select(readfd, 0, 0);
			}
		    }

		    // Stop select for writefds

		    for (let writefd of writefds_array) {

			if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

			    do_select(writefd, 1, 0);
			}
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

		if (exceptfds) {
		    for (let i=0; i < nfds; i++) {

			Module.HEAPU8[exceptfds+Math.floor(i/8)] = 0;
		    }
		}

		if (fd >= 0) {

		    if (rw && writefds) {

			Module.HEAPU8[writefds+Math.floor(fd/8)] = 1 << (fd % 8);
		    }
		    else if (readfds) {

			Module.HEAPU8[readfds+Math.floor(fd/8)] = 1 << (fd % 8);
		    }

		    wakeUp(1);
		}
		else {

		    wakeUp(0);
		}
	    };

	    let selectfds_array = [].concat(readfds_array, writefds_array);

	    let check_unknown_fds = (fds, callback) => {

		if (fds.length == 0) {
		    callback();
		    return;
		}

		let fd = fds.pop();

		if ( !(fd in Module['fd_table']) || !Module['fd_table'][fd] ) {

		    let buf_size = 256;

		    let buf2 = new Uint8Array(buf_size);

		    buf2[0] = 26; // IS_OPEN

		    let pid = Module.getpid();

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

		    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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
			    }

			    check_unknown_fds(fds, callback);
			    
			    return hid;
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
		else {
		    check_unknown_fds(fds, callback);
		}
	    }

	    check_unknown_fds(selectfds_array, () => {

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;
		    
		    if (msg2.buf[0] == (31|0x80)) {

			let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			let rw = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			//console.log("__syscall_pselect6: return of fd="+fd+", rw="+rw);
			
			notif_select(fd, rw);

			return hid;
		    }
		    else if (msg2.buf[0] == 62) { // END_OF_SIGNAL Signal received and handled

			//console.log("Signal has interrupted select syscall");
			
			//TODO: check flags
			
			wakeUp(-4); //EINTR

			return hid;
		    }
		    else {

			return -1;
		    }
		});

		let i = 0;

		// Start select for readfds
		
		for (let readfd of readfds_array) {

		    if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

			i++;
			do_select(readfd, 0, 1);
		    }
		}
		
		// Start select for writefds

		for (let writefd of writefds_array) {

		    if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

			i++;
			do_select(writefd, 1, 1);
		    }
		}

		if (i == 0) { // no fd for select

		    wakeUp(0);
		}
		else if (s >= 0) {

		    Module['select_timer'] = setTimeout(() => {

			Module['rcv_bc_channel'].unset_handler(hid);
			
			notif_select(-1, -1);
			
		    }, Math.floor(((s == 0) && (ns == 0))?5:s*1000+ns/1000000));
		}
	    });
	    
	});

	return ret;
    },
    __syscall_timerfd_create__sig: 'iii',
    __syscall_timerfd_create: function(clockid, flags) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let add_timerfd = (fd) => {

		//console.log("add_timerfd: fd="+fd);

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
	    };

	    let pid = Module.getpid();

	    if (pid == 1) {  // Called by resmgr

		Module['fd_table'].last_fd += 1;

		let fd = Module['fd_table'].last_fd;
		
		add_timerfd(fd);

		wakeUp(fd);
		
		return;
	    }
	    
	    let buf_size = 20;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 33; // TIMERFD_CREATE

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

	    // flags
	    buf2[16] = flags & 0xff;
	    buf2[17] = (flags >> 8) & 0xff;
	    buf2[18] = (flags >> 16) & 0xff;
	    buf2[19] = (flags >> 24) & 0xff;
	    
	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (33|0x80)) {

		    let fd = msg2.buf[20] | (msg2.buf[21] << 8) | (msg2.buf[22] << 16) |  (msg2.buf[23] << 24);

		    add_timerfd(fd);

		    wakeUp(fd);

		    return hid;
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

	//console.log('__syscall_timerfd_settime: fd='+fd+' flags='+flags+' new_value='+new_value+', curr_value='+curr_value);

	Module['fd_table'][fd].counter = 0;

	const int_sec = Module.HEAPU8[new_value] | (Module.HEAPU8[new_value+1] << 8) | (Module.HEAPU8[new_value+2] << 16) |  (Module.HEAPU8[new_value+3] << 24);
	const int_nsec = Module.HEAPU8[new_value+8] | (Module.HEAPU8[new_value+9] << 8) | (Module.HEAPU8[new_value+10] << 16) |  (Module.HEAPU8[new_value+11] << 24);
	const val_sec = Module.HEAPU8[new_value+16] | (Module.HEAPU8[new_value+17] << 8) | (Module.HEAPU8[new_value+18] << 16) |  (Module.HEAPU8[new_value+19] << 24);
	const val_nsec = Module.HEAPU8[new_value+24] | (Module.HEAPU8[new_value+25] << 8) | (Module.HEAPU8[new_value+26] << 16) |  (Module.HEAPU8[new_value+27] << 24);

	Module['fd_table'][fd].int_msec = int_sec * 1000 + int_nsec / 1000000;
	Module['fd_table'][fd].val_msec = val_sec * 1000 + val_nsec / 1000000;
	
	//console.log('__syscall_timerfd_settime: int='+int_sec+'s '+int_nsec+'ns ('+Module['fd_table'][fd].int_msec+'ms), val='+val_sec+'s '+val_nsec+'ns ('+Module['fd_table'][fd].val_msec+'ms)');

	if (Module['fd_table'][fd].timeout_id) {

	    if (Module['fd_table'][fd].timeout_interval)
		clearTimeout(Module['fd_table'][fd].timeout_id);
	    else
		clearInterval(Module['fd_table'][fd].timeout_id);
	    
	    Module['fd_table'][fd].timeout_id = 0;
	}

	if (Module['fd_table'][fd].val_msec) {

	    Module['fd_table'][fd].timeout_interval = true;
	    
	    Module['fd_table'][fd].timeout_id = setTimeout(() => {

		//console.log("Timeout !! "+fd);

		if (!Module['fd_table'][fd].timeout_id)
		    return;
		
		Module['fd_table'][fd].increase_counter();
		Module['fd_table'][fd].timeout_id = 0;
		
		if (Module['fd_table'][fd].int_msec) {

		    Module['fd_table'][fd].timeout_interval = false;
		    
		    Module['fd_table'][fd].timeout_id = setInterval(() => {

			//console.log("Interval !! "+fd);

			if (!Module['fd_table'][fd].timeout_id)
			    return;
			
			Module['fd_table'][fd].increase_counter();
			
		    }, Module['fd_table'][fd].int_msec);
		}
		
	    }, Module['fd_table'][fd].val_msec);
	}
    },
    __syscall_timerfd_gettime__sig: 'iip',
    __syscall_timerfd_gettime: function(fd, curr_value) {

	//console.log('__syscall_timerfd_gettime: fd='+fd);
    },
    __syscall_wait4__sig: 'iipii',
    __syscall_wait4: function (wpid, wstatus, options, rusage) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    //console.log("__syscall_wait4: wpid="+wpid+", options="+options);
	    
	    let buf_size = 24;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 37; // WAIT

	    let pid = Module.getpid();

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

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (37|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    if (!_errno) {

			let pid = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			Module.HEAPU8.set(msg2.buf.slice(20, 20+4), wstatus);

			wakeUp(pid);
		    }
		    else {

			wakeUp(-_errno);
		    }
		    
		    return hid;
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

	    //console.log("__syscall_exit_group");

	    let buf_size = 20;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 38; // EXIT

	    let pid = Module.getpid();

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

	    //console.log("__syscall_exit");

	    let buf_size = 20;
	    
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 38; // EXIT

	    let pid = Module.getpid();

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

	    //console.log("__syscall_lseek: off="+offset+", whence="+whence);

	    let do_lseek = () => {

		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 39; // SEEK

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    if (msg2.buf[0] == (39|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

			//console.log("bytes_read: "+bytes_read);

			if (!_errno) {

			    let off = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			    wakeUp(off);
			}
			else {
			
			    wakeUp(-_errno);
			}

			return hid;
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

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    return hid;
			}
			else {

			    wakeUp(-_errno);
			}

			return hid;
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
    __syscall_rt_sigaction__sig: 'iippi',
    __syscall_rt_sigaction: function (signum, act, oldact, sigsetsize) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 256;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 40; // SIGACTION

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    buf2[12] = signum & 0xff;
	    buf2[13] = (signum >> 8) & 0xff;
	    buf2[14] = (signum >> 16) & 0xff;
	    buf2[15] = (signum >> 24) & 0xff;

	    if (act)
		buf2.set(Module.HEAPU8.slice(act, act+140), 16);
	    else
		buf2.set(new Uint8Array(140), 16);

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (40|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    if (!_errno) {

			if (oldact)
			    Module.HEAPU8.set(msg2.buf.slice(16, 156), oldact);

			wakeUp(0);
		    }
		    else {

			wakeUp(-_errno);
		    }

		    return hid;
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
	    
	});

	return ret;
    },
    __syscall_rt_sigprocmask__sig: 'iippi',
    __syscall_rt_sigprocmask: function (how, set, oldset, sigsetsize) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 256;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 41; // SIGPROGMASK

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    buf2[12] = how & 0xff;
	    buf2[13] = (how >> 8) & 0xff;
	    buf2[14] = (how >> 16) & 0xff;
	    buf2[15] = (how >> 24) & 0xff;

	    buf2[16] = sigsetsize & 0xff;
	    buf2[17] = (sigsetsize >> 8) & 0xff;
	    buf2[18] = (sigsetsize >> 16) & 0xff;
	    buf2[19] = (sigsetsize >> 24) & 0xff;
	    
	    if (set)
		buf2.set(Module.HEAPU8.slice(set, set+sigsetsize), 20);
	    else
		buf2.set(new UInt8Array(sigsetsize), 20);

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (41|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    if (!_errno) {

			if (oldset)
			    Module.HEAPU8.set(msg2.buf.slice(20, 20+sigsetsize), oldset);

			wakeUp(0);
		    }
		    else {

			wakeUp(-_errno);
		    }

		    return hid;
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
	    
	});

	return ret;
    },
    __syscall_kill__sig: 'iii',
    __syscall_kill: function (pid, sig) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 256;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 42; // KILL

	    let my_pid = Module.getpid();

	    // pid
	    buf2[4] = my_pid & 0xff;
	    buf2[5] = (my_pid >> 8) & 0xff;
	    buf2[6] = (my_pid >> 16) & 0xff;
	    buf2[7] = (my_pid >> 24) & 0xff;
	    
	    buf2[12] = pid & 0xff;
	    buf2[13] = (pid >> 8) & 0xff;
	    buf2[14] = (pid >> 16) & 0xff;
	    buf2[15] = (pid >> 24) & 0xff;

	    buf2[16] = sig & 0xff;
	    buf2[17] = (sig >> 8) & 0xff;
	    buf2[18] = (sig >> 16) & 0xff;
	    buf2[19] = (sig >> 24) & 0xff;

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (42|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    wakeUp(-_errno);

		    return hid;
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
	});

	return ret;
    },
    __syscall_tkill__sig: 'iii',
    __syscall_tkill: function (tid, sig) {

    },

    __syscall_setitimer__sig: 'iipp',
    __syscall_setitimer: function (which, new_value, old_value) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 256;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 43; // SETITIMER

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	    
	    buf2[12] = which & 0xff;
	    buf2[13] = (which >> 8) & 0xff;
	    buf2[14] = (which >> 16) & 0xff;
	    buf2[15] = (which >> 24) & 0xff;

	    buf2.set(Module.HEAPU8.slice(new_value, new_value+16), 16);

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		//console.log("__syscall_setitimer "+msg2.buf[0]);

		if (msg2.buf[0] == (43|0x80)) {

		    if (old_value)
			Module.HEAPU8.set(msg2.buf.slice(16, 16+16), old_value);
		    
		    wakeUp(0);

		    return hid;
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
	});

	return ret;
    },

    __syscall_getitimer__sig: 'iip',
    __syscall_getitimer: function (which, old_value) {

	//TODO
    },

    __syscall_exa_release_signal__sig: 'ii',
    __syscall_exa_release_signal: function(signum) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 16;
	
	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 45; // EXA_RELEASE_SIGNAL

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    // signum
	    buf2[12] = signum & 0xff;
	    buf2[13] = (signum >> 8) & 0xff;
	    buf2[14] = (signum >> 16) & 0xff;
	    buf2[15] = (signum >> 24) & 0xff;

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (45|0x80)) {

		    //console.log(messageEvent);
		    
		    wakeUp(0);

		    //Module['rcv_bc_channel'].unset_handler(hid);

		    return hid;
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

    __syscall_exa_endofsignal__sig: 'ii',
    __syscall_exa_endofsignal: function(sig) {

	//console.log("__syscall_exa_endofsignal");

	setTimeout(() => {

	    //console.log("Nb handlers="+Module['rcv_bc_channel'].handlers.length);

	    let messageEvent = { data: {} };

	    let msg = messageEvent.data;

	    msg.buf = new Uint8Array(20);

	    msg.buf[0] = 62; // END_OF_SIGNAL

	    let pid = Module.getpid();

	    // pid
	    msg.buf[4] = pid & 0xff;
	    msg.buf[5] = (pid >> 8) & 0xff;
	    msg.buf[6] = (pid >> 16) & 0xff;
	    msg.buf[7] = (pid >> 24) & 0xff;
	    
	    msg.buf[12] = pid & 0xff;
	    msg.buf[13] = (pid >> 8) & 0xff;
	    msg.buf[14] = (pid >> 16) & 0xff;
	    msg.buf[15] = (pid >> 24) & 0xff;

	    msg.buf[16] = sig & 0xff;
	    msg.buf[17] = (sig >> 8) & 0xff;
	    msg.buf[18] = (sig >> 16) & 0xff;
	    msg.buf[19] = (sig >> 24) & 0xff;
	    
	    msg.from = Module['rcv_bc_channel'].name;

	    let bc = Module.get_broadcast_channel("/var/resmgr.peer");

	    bc.postMessage(msg);

	    let a = JSON.parse(savedAsyncify);
	    
	    Asyncify.callStackId = a.callStackId;
	    Asyncify.callStackIdToName = a.callStackIdToName;
	    Asyncify.callStackNameToId = a.callStackNameToId;
	    Asyncify.currData = a.currData;
	    Asyncify.handleSleepReturnValue = a.handleSleepReturnValue;
	    Asyncify.state = a.state;
	    Asyncify.exportCallStack = a.exportCallStack;
	    
	    _emscripten_stack_set_limits(a.stackBase,a.stackEnd);
	    stackRestore(a.stackTop);

	    if (Module['rcv_bc_channel'].handlers && (Module['rcv_bc_channel'].handlers.length > 0)) {

		let e = Module['rcv_bc_channel'].events.pop();

		let ret;
		
		if (e)
		    ret = Module['rcv_bc_channel'].handlers[Module['rcv_bc_channel'].handlers.length-1].handler(e);
		else
		    ret = Module['rcv_bc_channel'].handlers[Module['rcv_bc_channel'].handlers.length-1].handler(messageEvent);

		if (ret > 0) {
		    
		    Module['rcv_bc_channel'].unset_handler(ret);
		    
		    /*if (Module['rcv_bc_channel'].handlers.length > 0) {

			let e;
			
			while (e = Module['rcv_bc_channel'].events.pop()) {

			    console.log("Handle previous event !!");

			    ret = Module['rcv_bc_channel'].handlers[Module['rcv_bc_channel'].handlers.length-1].handler(e);

			    

			    if (ret > 0) {
				
				Module['rcv_bc_channel'].unset_handler(ret);
			    }
			}
		    }*/
		}
	    }
	    
	});

	return 0;
    },
    __syscall_setuid32__sig: 'ii',
    __syscall_setuid32: function(uid) {

	//TODO
	return 0;
    },
    __syscall_setgid32__sig: 'ii',
    __syscall_setgid32: function(gid) {

	//TODO
	return 0;
    },
    __syscall_uname__sig: 'ip',
    __syscall_uname: function(buf) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 12;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 48; // UNAME

	    let pid = Module.getpid();

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;
	  

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (48|0x80)) {

		    if (buf) {

			let len = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);
			
			Module.HEAPU8.set(msg2.buf.slice(16, 16+len), buf);
			wakeUp(0);
		    }
		    else {

			wakeUp(-14); //EFAULT
		    }

		    return hid;
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
	});

	return ret;
    },
    __syscall_utimensat__sig: 'iippi',
    __syscall_utimensat: function(dirFD, path_, times_, flags) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    wakeUp(0);
	});

	return ret;
    },
    __syscall_mmap2__sig: 'ppiiiii',
    __syscall_mmap2: function(addr, len, prot, flags, fd, off) {
	
	//console.log("__syscall_mmap2: fd="+fd+", off="+off);

	if (fd >= 0x7f000000) { // shm

	    let ptr = Module._malloc(len);

	    Module['shm'].fds[fd-0x7f000000].mem = ptr;
	    Module['shm'].fds[fd-0x7f000000].len = len;

	    return ptr;
	}
	else if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) && Module['fd_table'][fd].fb) {

	    // Frame buffer

	    return Module['fd_table'][fd].fb+off;
	    
	}
	else if ( (fd in Module['fd_table']) && (Module['fd_table'][fd]) && (Module['fd_table'][fd].peer == "/var/av.peer") ) {

	    // /dev/video0

	    let ptr = Module._malloc(Module.video0.buffers[off].length);

	    //console.log("mmap2: video0 off="+off+", ptr="+ptr);

	    Module.video0.buffers[off].ptr = ptr;
	    
	    return ptr;
	    
	}
	else {

	    return -1;
	}
    },
    __syscall_munmap__sig: 'ipi',
    __syscall_munmap: function(addr, length) {

	// TODO

	return 0;
    },

    __syscall_nanosleep__sig: 'ipp',
    __syscall_nanosleep: function(req, rem) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let int_msec = 0;

	    if (req) {

		const int_sec = Module.HEAPU8[req] | (Module.HEAPU8[req+1] << 8) | (Module.HEAPU8[req+2] << 16) |  (Module.HEAPU8[req+3] << 24);
		const int_nsec = Module.HEAPU8[req+8] | (Module.HEAPU8[req+9] << 8) | (Module.HEAPU8[req+10] << 16) |  (Module.HEAPU8[req+11] << 24);

		int_msec = Math.floor(int_sec * 1000 + int_nsec / 1000000);
	    }
	    
	    setTimeout(() => {

		wakeUp(0);
		
	    }, int_msec);
	});

	return ret;
    },
    __syscall_clock_nanosleep_time32__sig: 'iiipp',
    __syscall_clock_nanosleep_time32: function(clk, flags, req, rem) {

	//TODO
	return 0;
    },
    __syscall_fsync__sig: 'ii',
    __syscall_fsync: function(fd) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let do_fsync = () => {

		let buf_size = 16;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 49; // FSYNC

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		    let msg2 = messageEvent.data;

		    //console.log("__syscall_readv handler "+msg2.buf[0]);

		    if (msg2.buf[0] == (49|0x80)) {

			let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);
			
			wakeUp(-_errno);

			return hid;
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

		do_fsync();
	    }
	    else {
		let buf_size = 256;

		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 26; // IS_OPEN

		let pid = Module.getpid();

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

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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

			    do_fsync();

			    return hid;
			}
			else {

			    wakeUp(-1);
			}

			return hid;
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
    __syscall_setsockopt__sig: 'iiiipii',
    __syscall_setsockopt: function(fd, level, optname, optval, optlen) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let buf_size = 28+optlen;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 59; // SETSOCKOPT

	    let pid = Module.getpid();

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

	    // level
	    buf2[16] = level & 0xff;
	    buf2[17] = (level >> 8) & 0xff;
	    buf2[18] = (level >> 16) & 0xff;
	    buf2[19] = (level >> 24) & 0xff;

	    // optname
	    buf2[20] = optname & 0xff;
	    buf2[21] = (optname >> 8) & 0xff;
	    buf2[22] = (optname >> 16) & 0xff;
	    buf2[23] = (optname >> 24) & 0xff;

	    // optlen
	    buf2[24] = optlen & 0xff;
	    buf2[25] = (optlen >> 8) & 0xff;
	    buf2[26] = (optlen >> 16) & 0xff;
	    buf2[27] = (optlen >> 24) & 0xff;

	    buf2.set(Module.HEAPU8.slice(optval, optval+optlen), 28);

	    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

		let msg2 = messageEvent.data;

		if (msg2.buf[0] == (59|0x80)) {

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    wakeUp(-_errno);

		    return hid;
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
	    
	});

	return ret;
    },
    __syscall_epoll_create1__sig: 'ii',
    __syscall_epoll_create1: function(flags) {

	// TODO: multi thread

	if (!Module.epoll_fds)
	    Module.epoll_fds = new Array();

	Module.epoll_fds.push({
	    readfds_array: {},
	    writefds_array: {}
	});

	return 0x7d000000+Module.epoll_fds.length-1;
    },
    __syscall_epoll_ctl__sig: 'iiiip',
    __syscall_epoll_ctl: function(fd, op, fd2, ev) {

	let epoll = Module.epoll_fds[fd-0x7d000000];

	let events = Module.HEAPU8[ev] | (Module.HEAPU8[ev+1] << 8) | (Module.HEAPU8[ev+2] << 16) |  (Module.HEAPU8[ev+3] << 24);
	let ptr = Module.HEAPU8[ev+8] | (Module.HEAPU8[ev+9] << 8) | (Module.HEAPU8[ev+10] << 16) |  (Module.HEAPU8[ev+11] << 24);

	if (events & 0x01) { // EPOLLIN

	    if (op == 1) { // EPOLL_CTL_ADD

		epoll.readfds_array[fd2] = {

		    fd: fd2,
		    ptr: ptr
		};
	    }
	    else {

		// TODO
	    }
	}
	else {

	    // TODO
	}
	    
	return 0;
    },
    __syscall_epoll_wait__sig: 'iipii',
    __syscall_epoll_wait: function(epoll_fd, ev, cnt, to) {

	let ret = Asyncify.handleSleep(function (wakeUp) {

	    let epoll = Module.epoll_fds[epoll_fd-0x7d000000];

	    let do_select = (fd, rw, start) => {

		let buf_size = 256;
	
		let buf2 = new Uint8Array(buf_size);

		buf2[0] = 31; // SELECT

		let pid = Module.getpid();

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

		// once
		buf2[28] = 0;
		buf2[29] = 0;
		buf2[30] = 0;
		buf2[31] = 0;

		if (fd == 0x7e000000) { // wayland display

		    Module['fd_table'][fd].select(fd, rw, start, function(_fd, rw) {

			notif_select(_fd, rw);
		    });
		}
		else if (Module['fd_table'][fd].timerfd) { // timerfd

		    Module['fd_table'][fd].select(fd, rw, start, function(_fd, rw) {
			//console.log("timerfd notif_select _fd="+_fd);
			
			notif_select(_fd, rw);
		    });
		}
		else if (Module['fd_table'][fd].sock_ops) { // socket

		    Module['fd_table'][fd].sock_ops.select(getSocketFromFD(fd), fd, rw, start, function(_fd, rw) {

			//console.log("sock notif_select _fd="+_fd);

			notif_select(_fd, rw);
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

		    //console.log("__syscall_pselect6: peer="+Module['fd_table'][fd].peer);

		    let driver_bc = Module.get_broadcast_channel(Module['fd_table'][fd].peer);
		    
		    driver_bc.postMessage(msg);
		}
	    };

	    let notif_select = (fd, rw, pollhup) => {

		// Workaround before implement id in syscall
		if ( (fd != -1) && ((rw && !epoll.writefds_array[fd]) || (!rw && !epoll.readfds_array[fd]) ) )
		    return;

		if (Module['select_timer'])
		    clearTimeout(Module['select_timer']);
		
		// Stop select for readfds
		
		for (let readfd of Object.keys(epoll.readfds_array).map(Number)) {

		    if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

			do_select(readfd, 0, 0);
		    }
		}

		// Stop select for writefds

		for (let writefd of Object.keys(epoll.writefds_array).map(Number)) {

		    if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

			do_select(writefd, 1, 0);
		    }
		}

		if (fd >= 0) {

		    //console.log("!!! notif_select: fd="+fd);

		    let events = 0;

		    if (pollhup)
			events = 0x10; // EPOLLHUP
		    else if (rw == 0)
			events = 0x01; // EPOLLIN
		    else if (rw == 1)
			events = 0x04; // EPOLLOUT

		    let ptr;

		    if (rw == 0) {
			ptr = epoll.readfds_array[fd].ptr;
		    }
		    else {
			ptr = epoll.writefds_array[fd].ptr;
		    }

		    Module.HEAPU8[ev] = events & 0xff;
		    Module.HEAPU8[ev+1] = (events >> 8) & 0xff;
		    Module.HEAPU8[ev+2] = (events >> 16) & 0xff;
		    Module.HEAPU8[ev+3] = (events >> 24) & 0xff;

		    Module.HEAPU8[ev+8] = ptr & 0xff;
		    Module.HEAPU8[ev+9] = (ptr >> 8) & 0xff;
		    Module.HEAPU8[ev+10] = (ptr >> 16) & 0xff;
		    Module.HEAPU8[ev+11] = (ptr >> 24) & 0xff;

		    wakeUp(1);
		}
		else {

		    wakeUp(0);
		}
	    };

	    let selectfds_array = [].concat(Object.keys(epoll.readfds_array), Object.keys(epoll.writefds_array)).map(Number);

	    let check_unknown_fds = (fds, callback) => {

		if (fds.length == 0) {
		    callback();
		    return;
		}

		let fd = fds.pop();

		if ( !(fd in Module['fd_table']) || !Module['fd_table'][fd] ) {

		    let buf_size = 256;

		    let buf2 = new Uint8Array(buf_size);

		    buf2[0] = 26; // IS_OPEN

		    let pid = Module.getpid();

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

		    const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {

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
			    }

			    check_unknown_fds(fds, callback);
			    
			    return hid;
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
		else {
		    check_unknown_fds(fds, callback);
		}
	    }

	    check_unknown_fds(selectfds_array, () => {

		const hid = Module['rcv_bc_channel'].set_handler( (messageEvent) => {
		    //console.log("__syscall_epoll_wait: message received");

		    let msg2 = messageEvent.data;
		    
		    if (msg2.buf[0] == (31|0x80)) {

			let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);

			let rw = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);

			//console.log("__syscall_pselect6: return of fd="+fd+", rw="+rw);
			let pollhup = ((msg2.buf[28] | (msg2.buf[29] << 8) | (msg2.buf[30] << 16) |  (msg2.buf[31] << 24)) == 2);
			
			notif_select(fd, rw, pollhup);

			return hid;
		    }
		    else if (msg2.buf[0] == 62) { // END_OF_SIGNAL Signal received and handled

			//TODO: check flags
			
			wakeUp(-4); //EINTR

			return hid;
		    }
		    else {

			return -1;
		    }
		});

		let i = 0;

		// Start select for readfds
		
		for (let readfd of Object.keys(epoll.readfds_array).map(Number)) {

		    if ( (readfd in Module['fd_table']) && (Module['fd_table'][readfd]) ) {

			i++;
			do_select(readfd, 0, 1);
		    }
		}
		
		// Start select for writefds

		for (let writefd of Object.keys(epoll.writefds_array).map(Number)) {

		    if ( (writefd in Module['fd_table']) && (Module['fd_table'][writefd]) ) {

			i++;
			do_select(writefd, 1, 1);
		    }
		}

		if (i == 0) { // no fd for select

		    wakeUp(0);
		}
	    });
	    
	    
	});
	
	return ret;
    }
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
	/* Modified by Benoit Baudaux 21/07/2023 */
	/* no proxy by default because of async calls in parallel */
    library[x + '__proxy'] = /*'sync'*/false;
  }
#endif
}

for (var x in SyscallsLibrary) {
  wrapSyscallFunction(x, SyscallsLibrary, false);
}

mergeInto(LibraryManager.library, SyscallsLibrary);
