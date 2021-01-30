ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -std=gnu99 -Wall -Werror -D_POSIX_C_SOURCE=200809L \
	-D_BSD_SOURCE -D_DEFAULT_SOURCE

AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/common \
	-DSYSCONFDIR='"$(sysconfdir)"'

lib_LTLIBRARIES = libxcm.la
if CTL
lib_LTLIBRARIES += libxcmctl.la
endif

include_HEADERS = include/xcm.h include/xcm_compat.h include/xcm_addr.h \
	include/xcm_addr_compat.h include/xcm_attr.h include/xcm_attr_types.h

noinst_PROGRAMS = server client

bin_PROGRAMS = xcmpong
if XCM_TOOL
bin_PROGRAMS += xcm
endif
if CTL
bin_PROGRAMS += xcmctl
endif

check_PROGRAMS = xcmtest

# For information on how to update these numbers, see:
# https://www.gnu.org/software/libtool/manual/html_node/Libtool-versioning.html#Libtool-versioning
XCM_VERSION_CURRENT=@XCM_ABI_MINOR_VERSION@
XCM_VERSION_REVISION=0
XCM_VERSION_AGE=$(XCM_VERSION_CURRENT)

XCMCTL_VERSION_CURRENT=1
XCMCTL_VERSION_REVISION=0
XCMCTL_VERSION_AGE=$(XCMCTL_VERSION_CURRENT)

LIBXCM_SOURCES = libxcm/xcm.c libxcm/xcm_compat.c libxcm/xcm_addr.c \
	libxcm/xcm_addr_compat.c libxcm/xcm_tp.c libxcm/xcm_tp_ux.c \
	libxcm/xcm_tp_tcp.c libxcm/common_tp.c libxcm/tcp_attr.c \
	libxcm/log.c libxcm/xcm_dns_glibc.c libxcm/epoll_reg.c \
	libxcm/epoll_reg_set.c libxcm/active_fd.c common/util.c

if TLS
LIBXCM_SOURCES += libxcm/xcm_tp_tls.c libxcm/ctx_store.c \
	libxcm/xcm_tp_utls.c libxcm/log_tls.c
endif

if SCTP
LIBXCM_SOURCES += libxcm/xcm_tp_sctp.c
endif

if CTL
LIBXCM_SOURCES += libxcm/ctl.c common/common_ctl.c
endif

libxcm_la_SOURCES = $(LIBXCM_SOURCES)
libxcm_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libxcm/libxcm.vs \
	-version-info $(XCM_VERSION_CURRENT):$(XCM_VERSION_REVISION):$(XCM_VERSION_AGE)
libxcm_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/libxcm

if LTTNG
libxcm_la_SOURCES += lttng/xcm_lttng.c
libxcm_la_CPPFLAGS += -DXCM_LTTNG -I$(srcdir)/lttng
endif

if CTL
libxcmctl_la_SOURCES = libxcmctl/xcmc.c common/common_ctl.c common/util.c
libxcmctl_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libxcmctl/libxcmctl.vs \
	-version-info $(XCMCTL_VERSION_CURRENT):$(XCMCTL_VERSION_REVISION):$(XCMCTL_VERSION_AGE)
libxcmctl_la_CPPFLAGS = $(AM_CPPFLAGS) -DUT_STD_ASSERT -I$(srcdir)/libxcmctl
endif

xcmpong_SOURCES = tools/xcmpong.c common/util.c
# You might think of _CFLAGS setting as a no-op, but in fact this
# makes 'xcmmon/util.c' to be built in a separate version for
# 'umpong', which is needed since the other version is built by
# libtool.
xcmpong_CFLAGS = $(AM_CFLAGS)
xcmpong_CPPFLAGS = $(AM_CPPFLAGS) -DUT_STD_ASSERT
xcmpong_LDADD = libxcm.la
xcmpong_LDFLAGS = -lrt

if XCM_TOOL
xcm_SOURCES = tools/xcm.c tools/fdfwd.c common/util.c
# You might think of _CFLAGS setting as a no-op, but in fact this
# makes 'xcmmon/util.c' to be built in a separate version for
# 'umpong', which is needed since the other version is built by
# libtool.
xcm_CFLAGS = $(AM_CFLAGS)
xcm_CPPFLAGS = $(AM_CPPFLAGS) -DUT_STD_ASSERT
xcm_LDADD = libxcm.la
xcm_LDFLAGS = -levent
endif

if CTL
xcmctl_SOURCES = tools/xcmctl.c common/util.c
xcmctl_CFLAGS = $(AM_CFLAGS)
xcmctl_CPPFLAGS = $(AM_CPPFLAGS) -DUT_STD_ASSERT
xcmctl_LDADD = libxcmctl.la
endif

server_SOURCES = example/server.c
server_CFLAGS = $(AM_CFLAGS)
server_LDADD = libxcm.la

client_SOURCES = example/client.c
client_CFLAGS = $(AM_CFLAGS)
client_LDADD = libxcm.la

UTEST_SOURCES = test/utest/utest.c  test/utest/utestreport.c \
        test/utest/utesthumanreport.c
TEST_CPPFLAGS=-I$(srcdir)/test -I$(srcdir)/test/utest

XCMTEST_TESTCASE_SOURCES = test/xcm_testcases.c test/addr_testcases.c

xcmtest_SOURCES = $(XCMTEST_TESTCASE_SOURCES) $(UTEST_SOURCES) \
	common/util.c test/testutil.c test/pingpong.c
xcmtest_CPPFLAGS=$(AM_CPPFLAGS) $(TEST_CPPFLAGS) -DUT_STD_ASSERT
xcmtest_LDADD = libxcm.la
if CTL
xcmtest_LDADD += libxcmctl.la
endif
xcmtest_LDFLAGS = -no-install

doxygen: .doxygenerated

.doxygenerated: $(include_HEADERS)
	doxygen doc/doxygen.conf && touch .doxygenerated
	if [ -n "`command -v pdflatex`" ]; then \
		make -C doc/latex; \
	fi

clean-local:
	rm -rf doc/html
	rm -rf doc/latex
	rm -f common/*.d libxcm/*.d libxcmc/*.d example/*.d tools/*.d
	rm -f .doxygenerated

distclean-local:
	rm -rf autom4te.cache m4
	rm -f Makefile.in aclocal.m4 compile config.guess include/stamp-h1 \
		config.sub configure depcomp install-sh ltmain.sh missing \
		common/config.h.in py-compile
	find . -name \*~ -print0 | xargs -0 rm -f

xcmtest-run: xcmtest
	if [ "`id -u`" = 0 ]; then \
		./xcmtest -c -v -p 8 $(TESTS); \
	else \
		./xcmtest -c -v $(TESTS); \
	fi

if LTTNG
LTTNGWRAP=./test/with_lttng.sh
endif

if VALGRIND
xcmtest-run-valgrind: xcmtest
	cmd="$(LTTNGWRAP) valgrind --tool=memcheck --leak-check=full -q --suppressions=./test/lttng.supp --suppressions=./test/glibc.supp --num-callers=20 ./xcmtest -v -c"; \
	if [ "`id -u`" = 0 ]; then \
		IN_VALGRIND=1 $$cmd -p 8 $(TESTS); \
	else \
		IN_VALGRIND=1 $$cmd $(TESTS); \
	fi
endif

if PYTHON
xcm_PYTHON=python/xcm.py
xcmdir = $(pythondir)
python-test: libxcm.la
	LD_LIBRARY_PATH=$(builddir)/.libs ./python/xcmtest.py
endif

verify-versioning:
	./test/verify_versioning.py $(srcdir)/include/xcm.h \
		$(srcdir)/README.md $(builddir) \
		@XCM_ABI_MAJOR_VERSION@ @XCM_ABI_MINOR_VERSION@ \
		@XCM_MAJOR_VERSION@ @XCM_MINOR_VERSION@ \
		@XCM_PATCH_VERSION@

BASIC_TEST_TARGETS=xcmtest-run verify-versioning

if VALGRIND
TEST_TARGETS=xcmtest-run-valgrind $(BASIC_TEST_TARGETS)
else
TEST_TARGETS=$(BASIC_TEST_TARGETS)
endif

if PYTHON
TEST_TARGETS += python-test
endif

check-local: $(TEST_TARGETS)

count: clean
	wc -l `git ls-files | grep -E '\.[ch]{1}$$' | grep -v test/utest | grep -v example`
