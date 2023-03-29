#!/usr/bin/python3

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Ericsson AB

#
# echod.py -- a simple Python-based XCM echo server.
#
# This program is meant as an example how you can use XCM in
# non-blocking mode from Python.
#

import xcm
import sys
import errno
import asyncio

class Client:
    def __init__(self, event_loop, conn_sock):
        self.conn_sock = conn_sock
        conn_sock.set_target(xcm.SO_RECEIVABLE)
        self.msg = None
        self.event_loop = event_loop
        self.event_loop.add_reader(conn_sock, self.activate)
    def activate(self):
        try:
            if self.msg:
                self.conn_sock.send(self.msg)
                self.msg = None
            else:
                self.msg = self.conn_sock.receive()
                if len(self.msg) == 0:
                    self.terminate()
        except xcm.error as e:
            if e.errno != errno.EAGAIN:
                self.terminate()
        finally:
            if self.conn_sock != None:
                self.conn_sock.set_target(self.condition())
    def condition(self):
        if self.msg:
            return xcm.SO_SENDABLE
        else:
            return xcm.SO_RECEIVABLE
    def terminate(self):
        self.event_loop.remove_reader(self.conn_sock)
        self.conn_sock.close()
        self.conn_sock = None

class EchoServer:
    def __init__(self, event_loop, addr):
        self.event_loop = event_loop
        attrs = {"xcm.blocking": False, "xcm.service": "any"}
        self.sock = xcm.server(addr, attrs=attrs)
        self.sock.set_target(xcm.SO_ACCEPTABLE)
        self.event_loop.add_reader(self.sock, self.activate)
    def activate(self):
        try:
            conn_sock = self.sock.accept(attrs={"xcm.blocking": False})
            Client(self.event_loop, conn_sock)
        except xcm.error as e:
            if e.errno != errno.EAGAIN:
                raise e

def run(addr):
    event_loop = asyncio.new_event_loop()
    server = EchoServer(event_loop, addr)
    event_loop.run_forever()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <addr>" % sys.argv[0])
        sys.exit(1)
    run(sys.argv[1])
