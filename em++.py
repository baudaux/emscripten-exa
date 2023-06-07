#!/usr/bin/env python3
# Copyright 2011 The Emscripten Authors.  All rights reserved.
# Emscripten is available under two separate licenses, the MIT license and the
# University of Illinois/NCSA Open Source License.  Both these licenses can be
# found in the LICENSE file.

import sys
import emcc

emcc.run_via_emxx = True

if __name__ == '__main__':
  try:

    args = sys.argv

    # Added by Benoit Baudaux 1/04/2023
    if "-c" not in args and "-sBOOTSTRAPPING_STRUCT_INFO" not in args:
      args.append('-sASYNCIFY=1')
      args.append('-sEXIT_RUNTIME=1')
      
    sys.exit(emcc.run(args))
  except KeyboardInterrupt:
    emcc.logger.warning('KeyboardInterrupt')
    sys.exit(1)
