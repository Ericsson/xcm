# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Ericsson AB

import config
import errno
import gc
import pytest
import time
import xcm
import xtest


@pytest.fixture(scope='module', autouse=True)
def setup():
    xtest.setup_cert()
    yield
    xtest.teardown_cert()


@pytest.fixture(scope='function')
def server(request):
    try:
        addr = request.param
    except AttributeError:
        addr = xtest.TEST_ADDR

    server = xtest.echo_server(addr)

    time.sleep(0.5)

    yield addr

    server.terminate()
    server.join()


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


@pytest.mark.parametrize("server", xtest.TEST_MSG_ADDRS, indirect=True)
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


@pytest.mark.parametrize("server", xtest.TEST_ADDRS, indirect=True)
def test_echo(server):
    if xtest.is_bytestream(server):
        attrs = {
            "xcm.blocking": True,
            "xcm.service": "bytestream"
        }
        if xtest.is_tls_based(server):
            with open("%s/%s" % (xtest.CERT_DIR, "cert.pem"), "rb") as f:
                cert = f.read()
                attrs["tls.cert"] = cert
        conn = xcm.connect(server, attrs=attrs)
    else:
        conn = xcm.connect(server, 0)

    conn.set_blocking(False)
    conn.finish()
    conn.set_blocking(True)

    if xtest.is_tcp_based(server):
        conn.set_attr("tcp.keepalive_count", 99)
        assert conn.get_attr("tcp.keepalive_count") == 99
    else:
        with pytest.raises(FileNotFoundError):
            conn.set_attr("tcp.keepalive_count", 99)

    assert conn.get_attr("xcm.type") == "connection"

    with pytest.raises(PermissionError):
        conn.set_attr("xcm.remote_addr", "ux:foo")

    if xtest.is_tcp_based(server):
        assert conn.get_attr("tcp.rtt") > 0

    if xtest.is_tls_based(server):
        with open("%s/ski" % xtest.CERT_DIR, "rb") as f:
            key_id = f.read()
            assert conn.get_attr("tls.peer_subject_key_id") == key_id

    orig_msg = b'\x01\x02\x00\x03\x09\x02\x00\x04'
    conn.send(orig_msg)

    if xtest.is_bytestream(server):
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


@pytest.mark.parametrize("addr", xtest.TEST_ADDRS)
def test_server_attr(addr):
    if xtest.is_bytestream(addr):
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


@pytest.mark.parametrize("server", xtest.TEST_DNS_ADDRS, indirect=True)
def test_dns(server):
    attrs = {}

    if config.has_cares():
        attrs["dns.timeout"] = 1.0

    conn = xcm.connect(server, attrs=attrs)
    conn.close()


def test_gc_closes():
    sock = xcm.server(xtest.TEST_ADDR)
    del sock
    gc.collect()
    # getting EADDRINUSE in case socket is not closed
    sock = xcm.server(xtest.TEST_ADDR)
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
