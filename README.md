# Extensible Connection-oriented Messaging (XCM)

## Overview

XCM is a shared library implementing a messaging service on Linux. It
allows message-passing between processes on the same system, as well
between processes on different systems.

The library is good fit for an embedded system, with a light-weight
design and high performance. XCM is also well-suited for use in a
Cloud setting, such as communication between Kubernetes micro
services.

XCM has pluggable transports (handling the actual message
delivery). In combination with an URL-like addressing schema, it
allows applications to be transport agnostic, and one transport
suitable for one deployment can seamlessly be replaced with another,
in another deployment. The API semantics are the same, regardless of
underlying transport used.

XCM supports UNIX domain sockets for efficient local-only
communication, and TCP, TLS and SCTP for remote inter-process
communication. The service XCM provides is of the connection-oriented,
client-server type. It is not a message bus and does not implement the
publish-subscribe or broadcast patterns.

XCM does not require any other infrastructure or processes than the
library itself. It has no separate, background threads of its own, but
uses the application's thread(s) for all processing.

XCM does not make any assumption about which event loop is being used,
and thus frees the user to choose between libraries such as libev and
libevent, or the glib event loop (besides using XCM in blocking mode).

## User Manual

API documentation and a short user manual are available in
xcm.h. `make doxygen` will create HTML version. If the `pdflatex` tool
is installed, a PDF version will also be produced.

An online copy of this API version's documentation can be found here:
https://ericsson.github.io/xcm/api/0.15/

## Building

To build this software the system needs to have the following packages
(not including standard things like a C compiler):

* automake
* autoconf (2.63 and later are known to work, some older versions will not)
* libtool
* python (3.x)
* openssl (1.1.x, if UTLS or TLS transports are enabled)
* lttng-ust (including the dev and tools package) (if LTTng is enabled)
* libevent2 (if the 'xcm' command-line tool is enabled)
* doxygen and plantuml (for documentation)
* libsctp-dev (in case the SCTP transport is enabled)

Please see `./configure --help` for available build-time options. API
and ABI is identical regardless of options used.

When all packages are installed, run:
`autoreconf -i && ./configure <options> && make`

If you don't have OpenSSL installed, and don't need the TLS and UTLS
transports, those can be disabled with:
`./configure --disable-tls`

If you for some reason don't want LTTng tracing support, you may
disable LTTng UST with:
`./configure --disable-lttng`

If you don't need the 'xcm' command-line tool, you can avoid the
libevent dependency by using:
`./configure --disable-xcm-tool`

The control interface can be disabled by using:
`./configure --disable-ctl`

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

The test suite is partially an integration test, which includes the
Linux kernel, OpenSSL etc. There are known to be some race conditions
which can cause some tests to fail on busy or otherwise slow machines.
The known races are in the tests - not in the XCM library itself.
