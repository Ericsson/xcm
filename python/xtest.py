# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Ericsson AB

import config
import echod
import multiprocessing
import os
import random

CERT_DIR = "./test/data/cert/%d" % os.getpid()

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
    os.system("echo '%s' | ./test/tools/gencert.py" % CERT_CONF)
    os.environ["XCM_TLS_CERT"] = CERT_DIR


def teardown_cert():
    os.environ.pop("XCM_TLS_CERT")
    os.system("rm -rf %s" % CERT_DIR)


def echo_server(addr):
    p = multiprocessing.Process(target=echod.run, args=(addr,))
    p.start()
    return p


def rand_port():
    return random.randint(10000, 12000)


def rand_ux():
    return "ux:test-%d" % random.randint(0, 10000)


TEST_ADDR = "tcp:127.0.0.1:%d" % rand_port()

TEST_MSG_ADDRS = [
    rand_ux(),
    "tcp:127.0.0.1:%d" % rand_port()
]

TEST_ADDRS = TEST_MSG_ADDRS[:]
TEST_ADDRS.append("btcp:127.0.0.1:%d" % rand_port())

TEST_DNS_ADDRS = ["tcp:localhost:%d" % rand_port()]

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
    TEST_DNS_ADDRS.extend([
        "tls:localhost:%d" % rand_port(),
        "utls:localhost:%d" % rand_port()
    ])

if config.has_sctp():
    TEST_ADDRS.append("sctp:127.0.0.1:%d" % rand_port())
    TEST_MSG_ADDRS.append("sctp:127.0.0.1:%d" % rand_port())


def is_bytestream(addr):
    return addr.startswith("btls") or addr.startswith("btcp")


def is_tcp_based(addr):
    return addr.startswith("tcp") or addr.startswith("btcp") or \
        is_tls_based(addr)


def is_tls_based(addr):
    return addr.startswith("btls") or addr.startswith("tls")
