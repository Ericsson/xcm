#!/usr/bin/python3

import unittest
import xcm
import echod
import multiprocessing
import time
import random
import os
import config
import errno
import gc

def run_server(addr):
    echod.run(addr)

def echo_server(addr):
    p = multiprocessing.Process(target=run_server, args=(addr,))
    p.start()
    return p

TEST_ADDRS = [
    "ux:test-%d" % random.randint(0, 10000),
    "tcp:127.0.0.1:%d" % random.randint(10000, 12000)
]

if config.has_tls():
    TEST_ADDRS.extend([
        "tls:127.0.0.1:%d" % random.randint(10000, 12000),
        "utls:127.0.0.1:%d" % random.randint(10000, 12000)
    ])

if config.has_sctp():
    TEST_ADDRS.extend([
        "sctp:127.0.0.1:%d" % random.randint(10000, 12000)
    ])

class TestStringMethods(unittest.TestCase):
    def setUp(self):
        os.putenv("XCM_TLS_CERT", "./test/tls/with_root_cert")
    def tearDown(self):
        os.unsetenv("XCM_TLS_CERT")
    def test_echo(self):
        for addr in TEST_ADDRS:
            server_process = echo_server(addr)
            time.sleep(0.5)

            conn = xcm.connect(addr, 0)

            conn.set_blocking(False)
            conn.finish()
            conn.set_blocking(True)

            self.assertEqual(conn.get_attr("xcm.type"), "connection")

            if addr.startswith("tls") or addr.startswith("tcp"):
                self.assertGreater(conn.get_attr("tcp.rtt"), 0)

            orig_msg = b'\x01\x02\x00\x03\x09\x02\x00\x04'
            conn.send(orig_msg)
            ret_msg = conn.receive()
            self.assertEqual(ret_msg, orig_msg)

            conn.close()

            server_process.terminate()
            server_process.join()
    def test_server_attr(self):
        for addr in TEST_ADDRS:
            sock = xcm.server(addr)

            self.assertEqual(sock.get_attr("xcm.type"), "server")

            sock.set_blocking(False)
            sock.finish()
            sock.set_blocking(True)

            sock.close()
    def test_gc_closes(self):
        sock = xcm.server(TEST_ADDRS[0])
        del sock
        gc.collect()
        # getting EADDRINUSE in case socket is not closed
        sock = xcm.server(TEST_ADDRS[0])
        del sock
    def test_max_fd_exceeded(self):
        sockets = []
        # the assumption is that we will run out of fds fairly quickly
        try:
            while True:
                sockets.append(xcm.server("ux:py-xcmtest-%d" % len(sockets)))
        except xcm.error as e:
            assert e.errno == errno.EMFILE
        for s in sockets:
            s.close()
    def test_connection_refused(self):
        try:
            xcm.connect("ux:doesntexist", 0)
        except xcm.error as e:
            assert e.errno == errno.ECONNREFUSED
    def test_connection_enoent(self):
        try:
            xcm.connect("tcp:nonexistentdomain:4711", 0)
        except xcm.error as e:
            assert e.errno == errno.ENOENT

if __name__ == '__main__':
    unittest.main()
