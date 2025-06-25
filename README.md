# Extensible Connection-oriented Messaging (XCM)

## Overview

XCM is a shared library implementing an inter-process communication
service on Linux. It allows communication between processes on the
same system, as well as over a network.

The library is good fit for an embedded system, with a light-weight
design and high performance. XCM is also well-suited for use in a
Cloud setting, such as communication between Kubernetes micro
services.

XCM has pluggable transports, handling the actual data delivery. In
combination with an URL-like addressing scheme, it allows applications
to be transport agnostic, and one transport suitable for one
deployment can seamlessly be replaced with another, in another
deployment. The API semantics are the same, regardless of underlying
transport used.

A XCM transport either provides a messaging or a byte stream type
service.

XCM supports UNIX domain sockets for efficient local-only
communication, and TCP, TLS and SCTP for remote inter-process
communication. The service XCM provides is of the connection-oriented,
client-server type. It is not a message bus and does not implement the
publish-subscribe or broadcast patterns.

XCM does not depend any other processes or other type of
infrastructure than the library itself for its implementation. It has
no separate, background threads of its own, but uses the application's
thread(s) for all processing.

XCM does not make any assumption about which event loop is being used,
and thus frees the user to choose between libraries such as libev and
libevent, or the glib event loop (besides using XCM in blocking mode).

## User Manual

API documentation and a user manual are available in xcm.h. `make
doxygen` will create HTML version. Provided the `pdflatex` tool is
installed, `make doxygen-pdf` will produce a PDF version of the
document.

An online copy of this API version's documentation can be found here:
https://ericsson.github.io/xcm/api/0.26/

## Building

To build this software the system needs to have the following packages
(not including standard things like a C compiler):

* automake
* autoconf (2.63 and later are known to work, some older versions will not)
* libtool
* python (3.x, including the cryptography module if TLS is enabled)
* pytest
* c-ares (1.16.0 or later)
* openssl (1.1.1 or 3.x, if UTLS or TLS transports are enabled)
* lttng-ust (including the dev and tools package) (if LTTng is enabled)
* libevent2 (if the 'xcm' and 'xcmrelay' tools are enabled)
* doxygen and plantuml (for documentation)
* libsctp-dev (in case the SCTP transport is enabled)

Please see `./configure --help` for available build-time options. API
and ABI is identical regardless of options used.

When all packages are installed, run:
`autoreconf -i && ./configure <options> && make`

The BTLS, TLS and UTLS transports may be disabled (eliminating
the OpenSSL dependency):
`./configure --disable-tls`

LTTng support may also be disabled:
`./configure --disable-lttng`

XCM may be configured to use the glibc resolver instead of the c-ares
library:
`./configure --disable-cares`

Note: glibc getaddrinfo_a() uses background threads, performs worse
than c-ares, and has a tendency to leak memory in some corner cases.

The 'xcm' command-line tool may be disabled (eliminating the libevent
dependency):
`./configure --disable-xcm-tool`

The control interface can be disabled:
`./configure --disable-ctl`

### Ubuntu

To build on Ubuntu 22.04 LTS, install the following packages:

```
sudo apt install gcc make automake libtool libssl-dev libevent-dev \
     liblttng-ust-dev libc-ares-dev
```

### Static Library Builds

XCM depends on constructor functions to register transports into the
core library, and thus cannot be built statically.

## Testing

To execute the unit and component test suits, run:
`make check`

The test process doesn't require root permission, but some test cases
will be skipped for non-root users. Running as root will allow the
test suite to use network namespaces, and in such a way run many test
cases in parallel.

The test suite is in part an integration test, where the system under
test (SUT) includes the part of the Linux kernel and OpenSSL. Some
tests have race conditions, and may fail on busy or otherwise slow
machines. The races are in the tests - not in the XCM library itself.
