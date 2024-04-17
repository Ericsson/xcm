# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Ericsson AB

import config
import echod
import errno
import gc
import multiprocessing
import os
import pytest
import random
import time
import xcm

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


def setup_cert():
    os.system("echo '%s' | ./test/gencert.py" % CERT_CONF)
    os.putenv("XCM_TLS_CERT", CERT_DIR)


def teardown_cert():
    os.unsetenv("XCM_TLS_CERT")
    os.system("rm -rf %s" % CERT_DIR)


def run_server(addr):
    echod.run(addr)


def echo_server(addr):
    p = multiprocessing.Process(target=run_server, args=(addr,))
    p.start()
    return p


def rand_port():
    return random.randint(10000, 12000)


TEST_MSG_ADDRS = [
    "ux:test-%d" % random.randint(0, 10000),
    "tcp:127.0.0.1:%d" % rand_port()
]

TEST_ADDRS = TEST_MSG_ADDRS[:]
TEST_ADDRS.append("btcp:127.0.0.1:%d" % rand_port())

if config.has_tls():
    TEST_ADDRS.extend([
        "tls:127.0.0.1:%d" % rand_port(),
        "utls:127.0.0.1:%d" % rand_port(),
        "btls:127.0.0.1:%d" % rand_port()
    ])
    TEST_MSG_ADDRS.extend([
        "tls:127.0.0.1:%d" % rand_port(),
        "utls:127.0.0.1:%d" % rand_port()
    ])

if config.has_sctp():
    TEST_ADDRS.append("sctp:127.0.0.1:%d" % rand_port())
    TEST_MSG_ADDRS.append("sctp:127.0.0.1:%d" % rand_port())


@pytest.fixture(scope='module', autouse=True)
def setup():
    setup_cert()
    yield
    teardown_cert()


@pytest.fixture(scope='function')
def server(request):
    try:
        addr = request.param
    except AttributeError:
        addr = "tcp:127.0.0.1:%d" % rand_port()

    server = echo_server(addr)

    time.sleep(0.5)

    yield addr

    server.terminate()
    server.join()


def is_bytestream(addr):
    return addr.startswith("btls") or addr.startswith("btcp")


def is_tcp_based(addr):
    return addr.startswith("tcp") or addr.startswith("btcp") or \
        is_tls_based(addr)


def is_tls_based(addr):
    return addr.startswith("btls") or addr.startswith("tls")


def test_connect_attrs(server):
    attrs = {
        "xcm.local_addr": "tcp:127.0.0.2:0",
        "tcp.keepalive_interval": 99
    }
    conn = xcm.connect(server, attrs=attrs)

    assert conn.get_attr("xcm.local_addr").startswith("tcp:127.0.0.2")
    assert conn.get_attr("tcp.keepalive_interval") == 99
    assert conn.get_attr("tcp.connect_timeout") > 1e-6
    assert conn.get_attr("tcp.connect_timeout") < 10

    conn.close()


@pytest.mark.parametrize("server", TEST_MSG_ADDRS, indirect=True)
def test_connect_flags(server):
    conn = xcm.connect(server, xcm.NONBLOCK)
    assert not conn.is_blocking()

    finished = False
    while not finished:
        try:
            conn.finish()
            finished = True
        except BlockingIOError:
            time.sleep(0.1)

    conn.close()


@pytest.mark.parametrize("server", TEST_ADDRS, indirect=True)
def test_echo(server):
    if is_bytestream(server):
        attrs = {
            "xcm.blocking": True,
            "xcm.service": "bytestream"
        }
        if is_tls_based(server):
            with open("%s/%s" % (CERT_DIR, "cert.pem"), "rb") as f:
                cert = f.read()
                attrs["tls.cert"] = cert
        conn = xcm.connect(server, attrs=attrs)
    else:
        conn = xcm.connect(server, 0)

    conn.set_blocking(False)
    conn.finish()
    conn.set_blocking(True)

    if is_tcp_based(server):
        conn.set_attr("tcp.keepalive_count", 99)
        assert conn.get_attr("tcp.keepalive_count") == 99
    else:
        with pytest.raises(FileNotFoundError):
            conn.set_attr("tcp.keepalive_count", 99)

    assert conn.get_attr("xcm.type") == "connection"

    with pytest.raises(PermissionError):
        conn.set_attr("xcm.remote_addr", "ux:foo")

    if is_tcp_based(server):
        assert conn.get_attr("tcp.rtt") > 0

    if is_tls_based(server):
        with open("%s/ski" % CERT_DIR, "rb") as f:
            key_id = f.read()
            assert conn.get_attr("tls.peer_subject_key_id") == key_id

    orig_msg = b'\x01\x02\x00\x03\x09\x02\x00\x04'
    conn.send(orig_msg)

    if is_bytestream(server):
        ret_msg = conn.receive()
    else:
        conn.set_blocking(False)
        ret_msg = bytes()
        deadline = time.time() + 1
        while time.time() < deadline:
            try:
                ret_msg += conn.receive()
            except BlockingIOError:
                time.sleep(0.1)
        conn.set_blocking(True)

    assert ret_msg == orig_msg

    conn.close()


def test_server_attr():
    for addr in TEST_ADDRS:
        if is_bytestream(addr):
            sock = xcm.server(addr, attrs={"xcm.service": "bytestream"})
        else:
            sock = xcm.server(addr)

        assert sock.get_attr("xcm.type") == "server"

        sock.set_attr("xcm.blocking", False)
        assert not sock.get_attr("xcm.blocking")

        with pytest.raises(FileNotFoundError):
            sock.set_attr("xcm.tcp_keepalive_interval", 99)

        with pytest.raises(OSError) as exc_info:
            sock.set_attr("xcm.blocking", 17)
        assert exc_info.value.errno == errno.EINVAL

        sock.finish()
        sock.set_blocking(True)

        sock.close()


@pytest.mark.parametrize("server", ["tcp:localhost:%d" % rand_port()],
                         indirect=True)
def test_dns(server):
    attrs = {}

    if config.has_cares():
        attrs["dns.timeout"] = 1.0

    conn = xcm.connect(server, attrs=attrs)
    conn.close()


def test_gc_closes():
    sock = xcm.server(TEST_ADDRS[0])
    del sock
    gc.collect()
    # getting EADDRINUSE in case socket is not closed
    sock = xcm.server(TEST_ADDRS[0])
    del sock


def test_max_fd_exceeded():
    sockets = []
    # the assumption is that we will run out of fds fairly quickly
    try:
        while True:
            sockets.append(xcm.server("ux:py-xcmtest-%d" % len(sockets)))
    except xcm.error as e:
        assert e.errno == errno.EMFILE

    for s in sockets:
        s.close()


def test_connection_refused():
    with pytest.raises(ConnectionRefusedError) as exc_info:
        xcm.connect("ux:doesntexist")
    assert exc_info.value.errno == errno.ECONNREFUSED


def test_connection_enoent():
    with pytest.raises(FileNotFoundError) as exc_info:
        xcm.connect("tcp:nonexistentdomain:4711")
    assert exc_info.value.errno == errno.ENOENT


def test_connection_enoent_legacy():
    with pytest.raises(xcm.error) as exc_info:
        xcm.connect("tcp:nonexistentdomain:4711", 0)
    assert exc_info.value.errno == errno.ENOENT


def test_version():
    assert xcm.version().count(".") == 2
    assert xcm.version_api().count(".") == 1
