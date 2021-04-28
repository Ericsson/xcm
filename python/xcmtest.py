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

CERT_DIR = "./test/cert/%d" % os.getpid()

CERT_CONF = """
base-path: %s

certs:
  root:
    subject_name: root
    ca: True
  leaf:
    subject_name: leaf
    issuer: root

files:
  - type: key
    id: leaf
    path: key.pem
  - type: cert
    id: leaf
    path: cert.pem
  - type: ski
    id: leaf
    path: ski
  - type: bundle
    certs:
      - root
    path: tc.pem
""" % CERT_DIR

class TestXcm(unittest.TestCase):
    def setUp(self):
        os.system("echo '%s' | ./test/gencert.py" % CERT_CONF)
        os.putenv("XCM_TLS_CERT", CERT_DIR)
    def tearDown(self):
        os.unsetenv("XCM_TLS_CERT")
        os.system("rm -rf %s" % CERT_DIR)
    def test_connect_attrs(self):
        addr = "tcp:127.0.0.1:%d" % random.randint(10000, 12000)
        server_process = echo_server(addr)
        time.sleep(0.5)
        attrs = {
            "xcm.local_addr": "tcp:127.0.0.2:0",
            "tcp.keepalive_interval": 99
        }
        conn = xcm.connect(addr, attrs=attrs)
        self.assertTrue(conn.get_attr("xcm.local_addr").
                        startswith("tcp:127.0.0.2"))
        self.assertEqual(conn.get_attr("tcp.keepalive_interval"), 99)
        conn.close()
        server_process.terminate()
        server_process.join()
    def test_connect_flags(self):
        for addr in TEST_ADDRS:
            server_process = echo_server(addr)
            time.sleep(0.5)

            conn = xcm.connect(addr, xcm.NONBLOCK)
            self.assertFalse(conn.is_blocking())

            finished = False
            while not finished:
                try:
                    conn.finish()
                    finished = True
                except BlockingIOError:
                    time.sleep(0.1)

            conn.close()

            server_process.terminate()
            server_process.join()
    def test_echo(self):
        for addr in TEST_ADDRS:
            server_process = echo_server(addr)
            time.sleep(0.5)

            conn = xcm.connect(addr, 0)

            conn.set_blocking(False)
            conn.finish()
            conn.set_blocking(True)

            if addr.startswith("tls") or addr.startswith("tcp"):
                conn.set_attr("tcp.keepalive_count", 99)
                self.assertEqual(conn.get_attr("tcp.keepalive_count"), 99)
            else:
                self.assertRaises(FileNotFoundError, conn.set_attr,
                                  "tcp.keepalive_count", 99)

            self.assertEqual(conn.get_attr("xcm.type"), "connection")

            with self.assertRaises(PermissionError):
                conn.set_attr("xcm.remote_addr", "ux:foo")

            if addr.startswith("tls") or addr.startswith("tcp"):
                self.assertGreater(conn.get_attr("tcp.rtt"), 0)

            if addr.startswith("tls"):
                with open("%s/ski" % CERT_DIR, "rb") as f:
                    key_id = f.read()
                    self.assertEqual(conn.get_attr("tls.peer_subject_key_id"),
                                     key_id)

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

            sock.set_attr("xcm.blocking", False)
            self.assertEqual(sock.get_attr("xcm.blocking"), False)

            with self.assertRaises(FileNotFoundError):
                sock.set_attr("xcm.tcp_keepalive_interval", 99)

            with self.assertRaises(OSError) as cm:
                sock.set_attr("xcm.blocking", 17)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

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
            self.assertEqual(e.errno, errno.EMFILE)
        for s in sockets:
            s.close()
    def test_connection_refused(self):
        with self.assertRaises(ConnectionRefusedError) as cm:
            xcm.connect("ux:doesntexist")
        self.assertEqual(cm.exception.errno, errno.ECONNREFUSED)
    def test_connection_enoent(self):
        with self.assertRaises(FileNotFoundError) as cm:
            xcm.connect("tcp:nonexistentdomain:4711")
        self.assertEqual(cm.exception.errno, errno.ENOENT)
    def test_connection_enoent_legacy(self):
        with self.assertRaises(xcm.error) as cm:
            xcm.connect("tcp:nonexistentdomain:4711", 0)
        self.assertEqual(cm.exception.errno, errno.ENOENT)

if __name__ == '__main__':
    unittest.main()
