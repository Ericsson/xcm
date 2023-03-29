#!/usr/bin/python3

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Ericsson AB

import xcm
import sys

if len(sys.argv) == 3:
    raddr = sys.argv[1]
    msg = sys.argv[2]
    n = 1
elif len(sys.argv) == 4:
    raddr = sys.argv[1]
    msg = sys.argv[2]
    n = int(sys.argv[3])
    if n < 1:
        print("Number of iterations needs to be > 0")
        sys.exit(1)
else:
    print("Usage: %s <addr> <msg> [<iterations>]" % sys.argv[0])
    sys.exit(1)

conn = xcm.connect(raddr, 0)

for i in range(0, n):
    conn.send(msg.encode('utf-8'))

    res = conn.receive()

    print(res.decode('utf-8'))
