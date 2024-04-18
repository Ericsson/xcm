#!/usr/bin/python3

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Ericsson AB

import errno
import os
import pytest
import random
import signal
import subprocess
import threading
import time
import xcm
import xtest


@pytest.fixture(scope='module', autouse=True)
def setup():
    xtest.setup_cert()
    yield
    xtest.teardown_cert()


class Relay:
    def __init__(self, server_addr, client_addr):
        self.server_addr = server_addr
        self.client_addr = client_addr
        self.process = None

    def start(self):
        cmd = ["./xcmrelay", self.server_addr, self.client_addr]
        self.process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE)
        time.sleep(0.5)

    def stop(self):
        self.process.send_signal(signal.SIGHUP)
        assert self.process.wait() == 0


@pytest.fixture(scope='function')
def relay(request):
    while True:
        server_addr = random.choice(xtest.TEST_MSG_ADDRS)
        client_addr = random.choice(xtest.TEST_MSG_ADDRS)
        if server_addr != client_addr:
            break

    r = Relay(server_addr, client_addr)
    r.start()
    yield r
    r.stop()


def wire_up(relay):
    server = xcm.server(relay.client_addr)
    assert server is not None

    server.set_attr("xcm.blocking", False)

    relay_conn = xcm.connect(relay.server_addr)

    server_conn = None

    while True:
        try:
            if server_conn is None:
                server_conn = server.accept()
            else:
                server_conn.finish()
                break
        except xcm.error as e:
            if e.errno != errno.EAGAIN:
                raise

    relay_conn.set_attr("xcm.blocking", False)

    return (server, relay_conn, server_conn)


def test_basic(relay):
    server, relay_conn, server_conn = wire_up(relay)

    out_msg = os.urandom(random.randint(1, 65535))

    relay_conn.set_attr("xcm.blocking", True)
    relay_conn.send(out_msg)

    server_conn.set_attr("xcm.blocking", True)
    in_msg = server_conn.receive()

    assert in_msg == out_msg

    relay_conn.close()

    len(server_conn.receive()) == 0

    server.close()
    server_conn.close()


def test_backpressure(relay):
    server, relay_conn, server_conn = wire_up(relay)

    if random.choice([True, False]):
        in_conn = relay_conn
        out_conn = server_conn
    else:
        in_conn = server_conn
        out_conn = relay_conn

    out_msgs = []

    while True:
        try:
            out_msg = os.urandom(random.randint(1, 65535))
            out_conn.send(out_msg)
            out_msgs.append(out_msg)
        except xcm.error as e:
            if e.errno != errno.EAGAIN:
                raise
            elif len(out_msgs) > 0:
                break

    in_msgs = []

    while True:
        try:
            in_msg = in_conn.receive()
            in_msgs.append(in_msg)

            out_conn.finish()

        except xcm.error as e:
            if e.errno != errno.EAGAIN:
                raise
            elif len(out_msgs) == len(in_msgs):
                break

    assert in_msgs == out_msgs

    in_conn.set_attr("xcm.blocking", False)

    with pytest.raises(xcm.error) as exc_info:
        in_conn.receive()

    assert exc_info.value.errno == errno.EAGAIN

    server.close()
    relay_conn.close()
    server_conn.close()


def ping(conn):
    for _ in range(random.randint(1, 10)):
        out_msg = os.urandom(random.randint(1, 65535))

        conn.send(out_msg)

        in_msg = conn.receive()

        assert in_msg == out_msg


def test_echo(relay):
    server = xtest.echo_server(relay.client_addr)
    time.sleep(0.5)

    try:
        relay_conns = []
        while len(relay_conns) < 100:
            try:
                relay_conn = xcm.connect(relay.server_addr)
                relay_conns.append(relay_conn)
            except xcm.error as e:
                if e.errno == errno.EAGAIN:
                    time.sleep(0.1)
                else:
                    raise

        for _ in range(1000):
            threads = []
            for relay_num in random.sample(range(len(relay_conns)), 10):
                relay_conn = relay_conns[relay_num]
                thread = threading.Thread(target=ping, args=(relay_conn,))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

        for relay_conn in relay_conns:
            relay_conn.close()
    finally:
        server.terminate()
        server.join()
