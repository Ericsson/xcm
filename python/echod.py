#!/usr/bin/python

#
# echod.py -- a simple Python-based XCM echo server.
#
# This program is meant as an example how you can use XCM in
# non-blocking mode from Python.
#

import xcm
import sys
import select
import errno

def translate(select_rfds, select_wrfds, xcm_fds, xcm_events):
    for fd, event in zip(xcm_fds, xcm_events):
        if event&xcm.FD_READABLE:
            select_rfds.append(fd)
        if event&xcm.FD_WRITABLE:
            select_wrfds.append(fd)

def map_handler(m, fds, events, event_type, handler):
    for fd, event in zip(fds, events):
        if event & event_type:
            assert not fd in m
            m[fd] = handler

def call_ready(m, active):
    for fd in active:
        if fd in m:
            m[fd].ready()

class SocketDispatcher:
    def __init__(self):
        self.handlers = {}
    def add(self, handler, sock):
        self.handlers[handler] = sock
    def remove(self, handler):
        del self.handlers[handler]
    def complete_pending(self):
        pending = True
        while pending:
            pending = False
            for handler, sock in self.handlers.items():
                condition = handler.condition()
                if condition:
                    fds, events = sock.want(condition)
                    if len(fds) == 0:
                        handler.ready()
                        pending = True
    def gather_events(self):
        rfds = []
        wrfds = []
        rfd_handlers = {}
        wfd_handlers = {}
        for handler, sock in self.handlers.items():
            condition = handler.condition()
            fds, events = sock.want(condition)
            assert condition == 0 or len(fds) > 0
            translate(rfds, wrfds, fds, events)
            map_handler(rfd_handlers, fds, events, xcm.FD_READABLE, handler)
            map_handler(wfd_handlers, fds, events, xcm.FD_WRITABLE, handler)
        return (rfds, wrfds, rfd_handlers, wfd_handlers)
    def run(self):
        while True:
            self.complete_pending()
            rfds, wrfds, rfd_handlers, wfd_handlers = self.gather_events()
            ractive, wactive, eactive = select.select(rfds, wrfds, [])
            call_ready(rfd_handlers, ractive)
            call_ready(wfd_handlers, wactive)

class Client:
    def __init__(self, dispatcher, conn_sock):
        self.conn_sock = conn_sock
        self.msg = None
        self.dispatcher = dispatcher
        self.dispatcher.add(self, self.conn_sock)
    def ready(self):
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
                raise e
    def condition(self):
        if self.msg:
            return xcm.SO_SENDABLE
        else:
            return xcm.SO_RECEIVABLE
    def terminate(self):
        self.dispatcher.remove(self)
        self.conn_sock.close()

class EchoServer:
    def __init__(self, dispatcher, addr):
        self.sock = xcm.server(addr)
        self.sock.set_blocking(False)
        self.dispatcher = dispatcher
        self.dispatcher.add(self, self.sock)
    def ready(self):
        try:
            conn_sock = self.sock.accept()
            Client(self.dispatcher, conn_sock)
        except xcm.error as e:
            if e.errno != errno.EAGAIN:
                raise e
    def condition(self):
        return xcm.SO_ACCEPTABLE

def run(addr):
    dispatcher = SocketDispatcher()
    server = EchoServer(dispatcher, addr)
    dispatcher.run()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <addr>" % sys.argv[0])
        sys.exit(1)
    run(sys.argv[1])
