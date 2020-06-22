# XCM TODO

## Development Work

* Add a SOCK_STREAM-based UNIX socket transport which utilize batching
  (i.e. packing several XCM messages into a single read()/write()).
* Add libev/libevent/glib-based example programs.
* Extend the test suite with more negative testing.
* Make sure XCM builds on "all" versions of Linux.
* Make all the RET_ convience macros into GOTO_ variants, and add LTTng
  logging to all those error cases.

## API Extensions

* Consider hiding the xcm_want() machinery with multiple fds from the
  API user, and instead present a single, per-socket epoll instance.
* Added attribute/socket option type functions to allowing tweaking
  things like TCP keepalive options and allow binding a socket to
  a particular IP interface before the connect() call.
* Consider if the exception fdset (from select(2) needs to be handled as
  well as read/write events (and thus go into the fd_event enum).
* Consider the possibility to have timeouts for connect(), send() and
  receive().
* xcm_receive() should return ssize_t.

