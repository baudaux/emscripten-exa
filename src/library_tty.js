/**
 * @license
 * Copyright 2013 The Emscripten Authors
 * SPDX-License-Identifier: MIT
 */

mergeInto(LibraryManager.library, {
  $TTY__deps: ['$FS', '$intArrayFromString'],
#if !MINIMAL_RUNTIME
  $TTY__postset: function() {
    addAtInit('TTY.init();');
    addAtExit('TTY.shutdown();');
  },
#endif
  $TTY: {
    ttys: [],
    init: function () {
      // https://github.com/emscripten-core/emscripten/pull/1555
      // if (ENVIRONMENT_IS_NODE) {
      //   // currently, FS.init does not distinguish if process.stdin is a file or TTY
      //   // device, it always assumes it's a TTY device. because of this, we're forcing
      //   // process.stdin to UTF8 encoding to at least make stdin reading compatible
      //   // with text files until FS.init can be refactored.
      //   process['stdin']['setEncoding']('utf8');
      // }
    },
    shutdown: function() {
      // https://github.com/emscripten-core/emscripten/pull/1555
      // if (ENVIRONMENT_IS_NODE) {
      //   // inolen: any idea as to why node -e 'process.stdin.read()' wouldn't exit immediately (with process.stdin being a tty)?
      //   // isaacs: because now it's reading from the stream, you've expressed interest in it, so that read() kicks off a _read() which creates a ReadReq operation
      //   // inolen: I thought read() in that case was a synchronous operation that just grabbed some amount of buffered data if it exists?
      //   // isaacs: it is. but it also triggers a _read() call, which calls readStart() on the handle
      //   // isaacs: do process.stdin.pause() and i'd think it'd probably close the pending call
      //   process['stdin']['pause']();
      // }
    },
    register: function(dev, ops) {
      TTY.ttys[dev] = { input: [], output: [], ops: ops };
      FS.registerDevice(dev, TTY.stream_ops);
    },
    stream_ops: {
      open: function(stream) {
        var tty = TTY.ttys[stream.node.rdev];
        if (!tty) {
          throw new FS.ErrnoError({{{ cDefine('ENODEV') }}});
        }
        stream.tty = tty;
        stream.seekable = false;
      },
      close: function(stream) {
        // flush any pending line data
        stream.tty.ops.fsync(stream.tty);
      },
      fsync: function(stream) {
        stream.tty.ops.fsync(stream.tty);
      },
      read: function(stream, buffer, offset, length, pos /* ignored */) {
        if (!stream.tty || !stream.tty.ops.get_char) {
          throw new FS.ErrnoError({{{ cDefine('ENXIO') }}});
        }
        var bytesRead = 0;

        // Modified by Benoit Baudaux 08/11/2022

        /*for (var i = 0; i < length; i++) {
          var result;
          try {
            result = stream.tty.ops.get_char(stream.tty);
          } catch (e) {
            throw new FS.ErrnoError({{{ cDefine('EIO') }}});
          }
          if (result === undefined && bytesRead === 0) {
            throw new FS.ErrnoError({{{ cDefine('EAGAIN') }}});
          }
          if (result === null || result === undefined) break;
          bytesRead++;
          buffer[offset+i] = result;
        }
        if (bytesRead) {
          stream.node.timestamp = Date.now();
        }
        return bytesRead;*/

        const get_char_callback = function(result) {

          if (!(result === null || result === undefined)) {

            buffer[offset+bytesRead] = result;

            bytesRead++;

            if (bytesRead < length) {

              stream.tty.ops.get_char(stream.tty, get_char_callback, 0);
              return;
            }
          }

          if (bytesRead) {
            stream.node.timestamp = Date.now();
          }

          // result is null, no more char to read
          
          stream.read_callback(bytesRead,length);
        }

        if (length > 0) {

          stream.tty.ops.get_char(stream.tty, get_char_callback, 1);
        }
        else {

          stream.read_callback(0,0);
        }

        return -7777; // stream.read_callback is called once finished

      },
      write: function(stream, buffer, offset, length, pos) {
        if (!stream.tty || !stream.tty.ops.put_char) {
          throw new FS.ErrnoError({{{ cDefine('ENXIO') }}});
        }
        try {

          //console.log("write:"+length);

          for (var i = 0; i < length; i++) {

            //console.log("put_char:"+buffer[offset+i]);

            stream.tty.ops.put_char(stream.tty, buffer[offset+i]);
          }
        } catch (e) {
          throw new FS.ErrnoError({{{ cDefine('EIO') }}});
        }
        if (length) {
          stream.node.timestamp = Date.now();
        }
        return i;
      },
      // Modified by Benoit Baudaux 8/11/2022
      ioctl: function(stream, cmd, arg) {

        stream.tty.asynsify_wakeup = stream.asynsify_wakeup;

        const ret = stream.tty.ops.ioctl(stream.tty, cmd, arg);
        
        if (ret == 0) {

          stream.asynsify_wakeup_consumed = true;
        }

        return ret;
      }
    },
    default_tty_ops: {
      // get_char has 3 particular return values:
      // a.) the next character represented as an integer
      // b.) undefined to signal that no data is currently available
      // c.) null to signal an EOF
      get_char: function(tty, callback, blocking) {
        if (!tty.input.length) {
          var result = null;
#if ENVIRONMENT_MAY_BE_NODE
          if (ENVIRONMENT_IS_NODE) {
            // we will read data by chunks of BUFSIZE
            var BUFSIZE = 256;
            var buf = Buffer.alloc(BUFSIZE);
            var bytesRead = 0;

            try {
              bytesRead = fs.readSync(process.stdin.fd, buf, 0, BUFSIZE, -1);
            } catch(e) {
              // Cross-platform differences: on Windows, reading EOF throws an exception, but on other OSes,
              // reading EOF returns 0. Uniformize behavior by treating the EOF exception to return 0.
              if (e.toString().includes('EOF')) bytesRead = 0;
              else throw e;
            }

            if (bytesRead > 0) {
              result = buf.slice(0, bytesRead).toString('utf-8');
            } else {
              result = null;
            }
          } else
#endif
          // Modified by Benoit Baudaux 07/11/2022

          if (typeof window != 'undefined' &&
            typeof window.get_tty_input == 'function') {

              window.get_tty_input(function(result) {

                if (result !== null) {
                  tty.input = intArrayFromString(result, true);
                  callback(tty.input.shift());
                }
                else {
                  callback(null);
                }
              }, blocking);

              return 0;
          }
          else if (typeof window != 'undefined' &&
            typeof window.prompt == 'function') {
            // Browser.
            result = window.prompt('Input: ');  // returns null on cancel
            if (result !== null) {
              result += '\n';
            }
          } else if (typeof readline == 'function') {
            // Command line.
            result = readline();
            if (result !== null) {
              result += '\n';
            }
          }

          if (!result) {
            return null;
          }
          tty.input = intArrayFromString(result, true);
        }
        callback(tty.input.shift());
      },
      put_char: function(tty, val) {

        // Modified by Benoit Baudaux 08/11/2022
        /*if (val === null || val === {{{ charCode('\n') }}}) {
          out(UTF8ArrayToString(tty.output, 0));
          tty.output = [];
        } else {
          if (val != 0) tty.output.push(val); // val == 0 would cut text output off in the middle.
        }*/

        if (val) {

          tty.output.push(val);
          out(UTF8ArrayToString(tty.output, 0));
          tty.output = [];
        }
      },
      fsync: function(tty) {
        if (tty.output && tty.output.length > 0) {
          out(UTF8ArrayToString(tty.output, 0));
          tty.output = [];
        }
      },
      // Modified by Benoit Baudaux 8/11/2022
      ioctl: function(tty, cmd, arg) {

        let msg = {

          type: 2   // ioctl
        };

        switch(cmd) {

          case {{{ cDefine('TCGETS') }}}: {

            msg.op = 0;
            break;
          }
          case {{{ cDefine('TCSETS') }}}:
          case {{{ cDefine('TCSETSW') }}}:
          case {{{ cDefine('TCSETSF') }}}: {

            msg.op = 1;

            msg.termios = {

              c_iflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_iflag, '*') }}},
              c_oflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_oflag, '*') }}},
              c_cflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_cflag, '*') }}},
              c_lflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_lflag, '*') }}},
            };

            break;
          }
          case {{{ cDefine('TIOCGWINSZ') }}}: {

            console.log("tty.ioctl: TIOCGWINSZ");

            msg.op = 2;

            break;
          }

          default: return -{{{ cDefine('EINVAL') }}};
        }

        if (window.tty_ioctl) {
        
          window.tty_ioctl(msg, function(e) {

            if (e.type == 2) {    // IOCTL

              switch(e.op) {

                case 0:       // TCGETS

                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_iflag, 'e.termios.c_iflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_oflag, 'e.termios.c_oflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_cflag, 'e.termios.c_cflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_lflag, 'e.termios.c_lflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.__c_ispeed, 'e.termios.c_ispeed', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.__c_ospeed, 'e.termios.c_ospeed', 'i32') }}};

                  break;

                case 1:       // TCSETS

                  break;

                case 2:       // TIOCGWINSZ

                  {{{ makeSetValue('arg', C_STRUCTS.winsize.ws_row, 'e.winsize.ws_row', 'u16') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.winsize.ws_col, 'e.winsize.ws_col', 'u16') }}};

                  break;

                default:

                  break;
              }

              tty.asynsify_wakeup(e.res);
            }
            else {

              tty.asynsify_wakeup(-1);
            }
            
          });
        }
        else {

          tty.asynsify_wakeup(-1);
        }

        return 0;

      }
    },
    default_tty1_ops: {
      put_char: function(tty, val) {

        // Modified by Benoit Baudaux 08/11/2022
        /*if (val === null || val === {{{ charCode('\n') }}}) {

          // Modified by Benoit Baudaux 08/11/2022
      
          if (val === {{{ charCode('\n') }}})
            tty.output.push(val);

          err(UTF8ArrayToString(tty.output, 0));
          tty.output = [];
        } else {
          if (val != 0) tty.output.push(val);
        }*/

        if (val) {

          tty.output.push(val);
          out(UTF8ArrayToString(tty.output, 0));
          tty.output = [];
        }
      },
      fsync: function(tty) {
        if (tty.output && tty.output.length > 0) {
          err(UTF8ArrayToString(tty.output, 0));
          tty.output = [];
        }
      },
      // Modified by Benoit Baudaux 8/11/2022
      ioctl: function(tty, cmd, arg) {

        let msg = {

          type: 2   // ioctl
        };

        switch(cmd) {

          case {{{ cDefine('TCGETS') }}}: {

            msg.op = 0;
            break;
          }
          case {{{ cDefine('TCSETS') }}}:
          case {{{ cDefine('TCSETSW') }}}:
          case {{{ cDefine('TCSETSF') }}}: {

            msg.op = 1;

            msg.termios = {

              c_iflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_iflag, '*') }}},
              c_oflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_oflag, '*') }}},
              c_cflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_cflag, '*') }}},
              c_lflag: {{{ makeGetValue('arg', C_STRUCTS.termios.c_lflag, '*') }}},
            };

            break;
          }
          case {{{ cDefine('TIOCGWINSZ') }}}: {

            msg.op = 2;

            break;
          }

          default: return -{{{ cDefine('EINVAL') }}};
        }

        if (window.tty_ioctl) {
        
          window.tty_ioctl(msg, function(e) {

            if (e.type == 2) {    // IOCTL

              switch(e.op) {

                case 0:       // TCGETS

                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_iflag, 'e.termios.c_iflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_oflag, 'e.termios.c_oflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_cflag, 'e.termios.c_cflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.c_lflag, 'e.termios.c_lflag', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.__c_ispeed, 'e.termios.c_ispeed', 'i32') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.termios.__c_ospeed, 'e.termios.c_ospeed', 'i32') }}};

                  break;

                case 1:       // TCSETS

                  break;

                case 2:       // TIOCGWINSZ

                  {{{ makeSetValue('arg', C_STRUCTS.winsize.ws_row, 'e.winsize.ws_row', 'u16') }}};
                  {{{ makeSetValue('arg', C_STRUCTS.winsize.ws_col, 'e.winsize.ws_col', 'u16') }}};

                  break;

                default:

                  break;
              }

              tty.asynsify_wakeup(e.res);
            }
            else {

              tty.asynsify_wakeup(-1);
            }
            
          });
        }
        else {

          tty.asynsify_wakeup(-1);
        }

        return 0;

      }
    }
  }
});
