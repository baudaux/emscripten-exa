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
    path = SYSCALLS.getStr(path);
    FS.chdir(path);
    return 0;
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
    var old = SYSCALLS.getStreamFromFD(fd);
    return FS.createStream(old, 0).fd;
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

	    if (!Module['fd_table']) {

		Module['fd_table'] = {};
		Module['fd_table'].last_fd = 2;
	    }

	    if (window.frameElement.getAttribute('pid') != "1") {

		let bc = new BroadcastChannel("/tmp2/resmgr.peer");

		let buf = Module._malloc(256);

		Module.HEAPU8[buf] = 9; // SOCKET
		
		/*//padding
		  buf[1] = 0;
		  buf[2] = 0;
		  buf[3] = 0;*/

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		Module.HEAPU8[buf+4] = pid & 0xff;
		Module.HEAPU8[buf+5] = (pid >> 8) & 0xff;
		Module.HEAPU8[buf+6] = (pid >> 16) & 0xff;
		Module.HEAPU8[buf+7] = (pid >> 24) & 0xff;

		// errno
		Module.HEAPU8[buf+8] = 0x0;
		Module.HEAPU8[buf+9] = 0x0;
		Module.HEAPU8[buf+10] = 0x0;
		Module.HEAPU8[buf+11] = 0x0;

		// fd
		Module.HEAPU8[buf+12] = 0x0;
		Module.HEAPU8[buf+13] = 0x0;
		Module.HEAPU8[buf+14] = 0x0;
		Module.HEAPU8[buf+15] = 0x0;
		
		// domain
		Module.HEAPU8[buf+16] = domain & 0xff;
		Module.HEAPU8[buf+17] = (domain >> 8) & 0xff;
		Module.HEAPU8[buf+18] = (domain >> 16) & 0xff;
		Module.HEAPU8[buf+19] = (domain >> 24) & 0xff;

		// type
		Module.HEAPU8[buf+20] = type & 0xff;
		Module.HEAPU8[buf+21] = (type >> 8) & 0xff;
		Module.HEAPU8[buf+22] = (type >> 16) & 0xff;
		Module.HEAPU8[buf+23] = (type >> 24) & 0xff;

		// protocol
		Module.HEAPU8[buf+24] = protocol & 0xff;
		Module.HEAPU8[buf+25] = (protocol >> 8) & 0xff;
		Module.HEAPU8[buf+26] = (protocol >> 16) & 0xff;
		Module.HEAPU8[buf+27] = (protocol >> 24) & 0xff;
		
		let buf2 = Module.HEAPU8.slice(buf,buf+256);

		if (!Module['last_bc'])
		    Module['last_bc'] = 1;
		else
		    Module['last_bc'] += 1;

		let socket_name = "socket."+window.frameElement.getAttribute('pid')+"."+Module['fd_table'].last_bc;
		let socket_bc = new BroadcastChannel(socket_name);

		socket_bc.onmessage = (messageEvent) => {

		    socket_bc.close();

		    let msg2 = messageEvent.data;

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    if (msg2.buf[0] == (9|0x80)) {

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
				sock_ops: SOCKFS.unix_dgram_sock_ops
#endif
			    };

			    Module['fd_table'][fd] = sock;

			    wakeUp(fd);
			}
			else {

			    wakeUp(-1);
			}
		    }
		};

		let msg = {

		    from: socket_name,
		    buf: buf2,
		    len: 256
		};
		
		bc.postMessage(msg);

		Module._free(buf);
	    }
	    else {

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
		    sock_ops: SOCKFS.unix_dgram_sock_ops
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
    if (size === 0) return -{{{ cDefine('EINVAL') }}};
    var cwd = FS.cwd();
    var cwdLengthInBytes = lengthBytesUTF8(cwd) + 1;
    if (size < cwdLengthInBytes) return -{{{ cDefine('ERANGE') }}};
    stringToUTF8(cwd, buf, size);
    return cwdLengthInBytes;
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
    path = SYSCALLS.getStr(path);
    return SYSCALLS.doStat(FS.stat, path, buf);
  },
  __syscall_lstat64__sig: 'ipp',
  __syscall_lstat64: function(path, buf) {
    path = SYSCALLS.getStr(path);
    return SYSCALLS.doStat(FS.lstat, path, buf);
  },
  __syscall_fstat64__sig: 'iip',
  __syscall_fstat64: function(fd, buf) {
    var stream = SYSCALLS.getStreamFromFD(fd);
    return SYSCALLS.doStat(FS.stat, stream.path, buf);
  },
  __syscall_fchown32: function(fd, owner, group) {
    FS.fchown(fd, owner, group);
    return 0;
  },
  __syscall_getdents64__sig: 'iipi',
  __syscall_getdents64: function(fd, dirp, count) {
    var stream = SYSCALLS.getStreamFromFD(fd)
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
    return pos;
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

		let bc = new BroadcastChannel("/tmp2/resmgr.peer");

		let buf = Module._malloc(1256);

		Module.HEAPU8[buf] = 11; // OPEN

		/*//padding
		  buf[1] = 0;
		  buf[2] = 0;
		  buf[3] = 0;*/

		let pid = parseInt(window.frameElement.getAttribute('pid'));

		// pid
		Module.HEAPU8[buf+4] = pid & 0xff;
		Module.HEAPU8[buf+5] = (pid >> 8) & 0xff;
		Module.HEAPU8[buf+6] = (pid >> 16) & 0xff;
		Module.HEAPU8[buf+7] = (pid >> 24) & 0xff;

		// errno
		Module.HEAPU8[buf+8] = 0x0;
		Module.HEAPU8[buf+9] = 0x0;
		Module.HEAPU8[buf+10] = 0x0;
		Module.HEAPU8[buf+11] = 0x0;

		// fd
		Module.HEAPU8[buf+12] = 0x0;
		Module.HEAPU8[buf+13] = 0x0;
		Module.HEAPU8[buf+14] = 0x0;
		Module.HEAPU8[buf+15] = 0x0;

		// remote fd
		Module.HEAPU8[buf+16] = 0x0;
		Module.HEAPU8[buf+17] = 0x0;
		Module.HEAPU8[buf+18] = 0x0;
		Module.HEAPU8[buf+19] = 0x0;

		// flags
		Module.HEAPU8[buf+20] = flags & 0xff;
		Module.HEAPU8[buf+21] = (flags >> 8) & 0xff;
		Module.HEAPU8[buf+22] = (flags >> 16) & 0xff;
		Module.HEAPU8[buf+23] = (flags >> 24) & 0xff;

		// mode
		// TODO

		// pathname
		stringToUTF8(UTF8ToString(path), buf+140, 1024);

		let buf2 = Module.HEAPU8.slice(buf, buf+1256);

		if (!Module['last_bc'])
		    Module['last_bc'] = 1;
		else
		    Module['last_bc'] += 1;
		
		let open_name = "open."+window.frameElement.getAttribute('pid')+"."+Module['last_bc'];

		let open_bc = new BroadcastChannel(open_name);

		//first_response = true;

		open_bc.onmessage = (messageEvent) => {

		    //console.log("open_bc.onmessage");
		    //console.log(messageEvent);

		    open_bc = null;

		    let msg2 = messageEvent.data;

		    let _errno = msg2.buf[8] | (msg2.buf[9] << 8) | (msg2.buf[10] << 16) |  (msg2.buf[11] << 24);

		    /*if (first_response) { // first response comes from resmgr

			first_response = false;

			msg2.buf[0] = 11;

			msg2.from = open_name;

			let peer = UTF8ArrayToString(msg2.buf, 26, 108);

			console.log("forward to "+peer);
			
			let open_driver_bc = new BroadcastChannel(peer);

			open_driver_bc.postMessage(msg2);
		    }
		    else {*/

			if (msg2.buf[0] == (11|0x80)) {

			    if (_errno == 0) {

				let fd = msg2.buf[12] | (msg2.buf[13] << 8) | (msg2.buf[14] << 16) |  (msg2.buf[15] << 24);
				let remote_fd = msg2.buf[16] | (msg2.buf[17] << 8) | (msg2.buf[18] << 16) |  (msg2.buf[19] << 24);
				let flags = msg2.buf[20] | (msg2.buf[21] << 8) | (msg2.buf[22] << 16) |  (msg2.buf[23] << 24);
				let mode = msg2.buf[24] | (msg2.buf[25] << 8);
				let type = msg2.buf[26];
				let major = msg2.buf[28] | (msg2.buf[29] << 8);
				let minor = msg2.buf[30] | (msg2.buf[31] << 8);
				let peer = UTF8ArrayToString(msg2.buf, 32, 108);

				if (!Module['fd_table']) {

				    Module['fd_table'] = {};
				}

				// create our internal socket structure
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

				wakeUp(-1);
			    }
			}
		};

		let msg = {

		    from: open_name,
		    buf: buf2,
		    len: 1256
		};
		
		bc.postMessage(msg);

		Module._free(buf);
	    }
	});

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
    path = SYSCALLS.getStr(path);
    var nofollow = flags & {{{ cDefine('AT_SYMLINK_NOFOLLOW') }}};
    var allowEmpty = flags & {{{ cDefine('AT_EMPTY_PATH') }}};
    flags = flags & (~{{{ cDefine('AT_SYMLINK_NOFOLLOW') | cDefine('AT_EMPTY_PATH') }}});
#if ASSERTIONS
    assert(!flags, flags);
#endif
    path = SYSCALLS.calculateAt(dirfd, path, allowEmpty);
    return SYSCALLS.doStat(nofollow ? FS.lstat : FS.stat, path, buf);
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
  __syscall_readlinkat__sig: 'vippp',
  __syscall_readlinkat: function(dirfd, path, buf, bufsize) {
    path = SYSCALLS.getStr(path);
    path = SYSCALLS.calculateAt(dirfd, path);
    if (bufsize <= 0) return -{{{ cDefine('EINVAL') }}};
    var ret = FS.readlink(path);

    var len = Math.min(bufsize, lengthBytesUTF8(ret));
    var endChar = HEAP8[buf+len];
    stringToUTF8(ret, buf, bufsize+1);
    // readlink is one of the rare functions that write out a C string, but does never append a null to the output buffer(!)
    // stringToUTF8() always appends a null byte, so restore the character under the null byte after the write.
    HEAP8[buf+len] = endChar;
    return len;
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

	    // TODO: fork from other process than resmgr

	    if (!Module.child_pid) {

		// Reserve 1 for resmgr, so start at 2
		
		Module.child_pid = 2;
	    }
	    else {

		Module.child_pid += 1;
	    }

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
	});

	return ret;
    },
    // Modified by Benoit Baudaux 22/12/2020
    __syscall_execve__sig: 'ippp',
    __syscall_execve: function(pathname, argv, envp) {

	// Use Asyncify for not returning from execve
	
	let ret = Asyncify.handleSleep(function (wakeUp) {

	    // Remove name property of window for process to be loaded fully with no fork mechanism
	    window.name = "";

	    //TODO: use argv and envp
	    window.frameElement.src = SYSCALLS.getStr(pathname)+"/exa/exa.html";
	});
    },

    /* Modified by Benoit Baudaux 5/1/2023 */
    __syscall_write__sig: 'iipi',
    __syscall_write: function(fd, buf, count) {
	
	let ret = Asyncify.handleSleep(function (wakeUp) {
	
	    let len = count;

	    /*for (var i = 0; i < iovcnt; i++) {
		len += {{{ makeGetValue('iov', C_STRUCTS.iovec.iov_len, '*') }}};
		iov += {{{ C_STRUCTS.iovec.__size__ }}};
	    }*/

	    let buf_size = 20+len;

	    let buf2 = new Uint8Array(buf_size);

	    buf2[0] = 13; // WRITE

	    let pid = parseInt(window.frameElement.getAttribute('pid'));

	    // pid
	    buf2[4] = pid & 0xff;
	    buf2[5] = (pid >> 8) & 0xff;
	    buf2[6] = (pid >> 16) & 0xff;
	    buf2[7] = (pid >> 24) & 0xff;

	    let remote_fd = (fd >= 0)? Module['fd_table'][fd].remote_fd : -1;

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

	    /*buf_size = 20;

	    for (var i = 0; i < iovcnt; i++) {
		let ptr = {{{ makeGetValue('iov', C_STRUCTS.iovec.iov_base, '*') }}};
		let l = {{{ makeGetValue('iov', C_STRUCTS.iovec.iov_len, '*') }}};

		buf.set(HEAPU8.slice(ptr,ptr+l),buf_size);
		
		buf_size += l;
		
		iov += {{{ C_STRUCTS.iovec.__size__ }}};
		}*/

	    buf2.set(HEAPU8.slice(buf,buf+len),20);

	    if (!Module['last_bc'])
		Module['last_bc'] = 1;
	    else
		Module['last_bc'] += 1;

	    let write_name = "write."+window.frameElement.getAttribute('pid')+"."+Module['last_bc'];

	    let write_bc = new BroadcastChannel(write_name);

	    write_bc.onmessage = (messageEvent) => {

		write_bc.close();
		
		wakeUp(0); // TODO: size
	    };

	    let msg = {

		from: write_name,
		buf: buf2,
		len: buf_size
	    };

	    //let write_driver_bc = new BroadcastChannel(Module['fd_table'][fd].peer);
	    let write_driver_bc = new BroadcastChannel("/tmp2/tty.peer");
	    
	    write_driver_bc.postMessage(msg);
	});
    
    return ret;
    },
    /* Modified by Benoit Baudaux 8/1/2023 */
    __syscall_writev__sig: 'iippp',
    __syscall_writev: function(fd, iov, iovcnt, pnum) {

	// TODO
	return 0;
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

	    if (!Module['last_bc'])
		Module['last_bc'] = 1;
	    else
		Module['last_bc'] += 1;
	    
	    let close_name = "close."+window.frameElement.getAttribute('pid')+"."+Module['last_bc'];

	    let close_bc = new BroadcastChannel(close_name);

	    close_bc.onmessage = (messageEvent) => {

		//console.log(messageEvent);

		close_bc.close();
		
		wakeUp(0); // TODO
	    };

	    let msg = {

		from: close_name,
		buf: buf2,
		len: buf_size
	    };

	    let bc = new BroadcastChannel("/tmp2/resmgr.peer");

	    bc.postMessage(msg);

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
