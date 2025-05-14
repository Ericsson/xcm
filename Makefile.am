ACLOCAL_AMFLAGS = -I m4

PYTEST=py.test-3

AM_CFLAGS = -std=gnu99 -Wall -Wmissing-prototypes -D_POSIX_C_SOURCE=200809L \
	-D_BSD_SOURCE -D_DEFAULT_SOURCE -D_GNU_SOURCE

AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/common -I$(builddir)/include \
	-DSYSCONFDIR='"$(sysconfdir)"'

lib_LTLIBRARIES = libxcm.la
if CTL
lib_LTLIBRARIES += libxcmctl.la
endif

include_HEADERS = include/xcm.h include/xcm_compat.h include/xcm_addr.h \
	include/xcm_addr_compat.h include/xcm_attr.h include/xcm_attr_map.h \
	include/xcm_attr_types.h include/xcm_version.h

if EXAMPLES
noinst_PROGRAMS = server client echod
endif

bin_PROGRAMS = xcmpong
if XCM_TOOL
bin_PROGRAMS += xcm xcmrelay
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

libxcm_la_SOURCES = \
	common/slist.c \
	common/util.c \
	libxcm/core/attr_node.c \
	libxcm/core/attr_path.c \
	libxcm/core/attr_tree.c \
	libxcm/core/log.c \
	libxcm/core/log_attr_tree.c \
	libxcm/core/timer_mgr.c \
	libxcm/core/xcm.c \
	libxcm/core/xcm_addr.c \
	libxcm/core/xcm_addr_compat.c \
	libxcm/core/xcm_attr_map.c \
	libxcm/core/xcm_compat.c \
	libxcm/core/xcm_version.c \
	libxcm/core/xpoll.c \
	libxcm/tp/common/active_fd.c \
	libxcm/tp/common/common_tp.c \
	libxcm/tp/common/dns_attr.c \
	libxcm/tp/common/log_tp.c \
	libxcm/tp/common/xcm_tp.c \
	libxcm/tp/dns/xcm_dns.c \
	libxcm/tp/tcp/tconnect.c \
	libxcm/tp/tcp/tcp_attr.c \
	libxcm/tp/tcp/xcm_tp_btcp.c \
	libxcm/tp/tcp/xcm_tp_tcp.c \
	libxcm/tp/ux/xcm_tp_ux.c

libxcm_la_LDFLAGS = @ANL_LIBS@ @CARES_LIBS@ @SSL_LIBS@ \
	-Wl,--version-script=$(srcdir)/libxcm/libxcm.vs \
	-version-info $(XCM_VERSION_CURRENT):$(XCM_VERSION_REVISION):$(XCM_VERSION_AGE)
libxcm_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/libxcm/core \
	-I$(srcdir)/libxcm/tp/common -I$(srcdir)/libxcm/tp/ux \
	-I$(srcdir)/libxcm/tp/tcp -I$(srcdir)/libxcm/tp/dns

if CARES
libxcm_la_SOURCES += libxcm/tp/dns/xcm_dns_cares.c
else
libxcm_la_SOURCES += libxcm/tp/dns/xcm_dns_glibc.c
endif

if TLS
libxcm_la_SOURCES += \
	libxcm/tp/tls/cert.c \
	libxcm/tp/tls/ctx_store.c \
	libxcm/tp/tls/item.c \
	libxcm/tp/tls/log_tls.c \
	libxcm/tp/tls/xcm_tp_btls.c \
	libxcm/tp/tls/xcm_tp_tls.c \
	libxcm/tp/tls/xcm_tp_utls.c
libxcm_la_CPPFLAGS += -I$(srcdir)/libxcm/tp/tls
# Assure no calls are made to OpenSSL APIs deprecated in the oldest
# supported version (1.1.0).
libxcm_la_CPPFLAGS += -DOPENSSL_NO_DEPRECATED -DOPENSSL_API_COMPAT=0x10100000L
endif

if SCTP
libxcm_la_SOURCES += libxcm/tp/sctp/xcm_tp_sctp.c
endif

if CTL
libxcm_la_SOURCES += libxcm/ctl/ctl.c common/common_ctl.c
libxcm_la_CPPFLAGS += -I$(srcdir)/libxcm/ctl
endif

if LTTNG
libxcm_la_SOURCES += lttng/xcm_lttng.c
libxcm_la_CPPFLAGS += -DXCM_LTTNG -I$(srcdir)/lttng
libxcm_la_LDFLAGS += @LTTNG_LIBS@
endif

if CTL
libxcmctl_la_SOURCES = libxcmctl/xcmc.c common/common_ctl.c common/util.c
libxcmctl_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libxcmctl/libxcmctl.vs \
	-version-info $(XCMCTL_VERSION_CURRENT):$(XCMCTL_VERSION_REVISION):$(XCMCTL_VERSION_AGE)
libxcmctl_la_CPPFLAGS = $(AM_CPPFLAGS) -DUT_STD_ASSERT -I$(srcdir)/libxcmctl
endif

xcmpong_SOURCES = tools/xcmpong/main.c common/util.c
# You might think of _CFLAGS setting as a no-op, but in fact this
# makes 'xcmmon/util.c' to be built in a separate version for
# 'umpong', which is needed since the other version is built by
# libtool.
xcmpong_CFLAGS = $(AM_CFLAGS)
xcmpong_CPPFLAGS = $(AM_CPPFLAGS) -DUT_STD_ASSERT
xcmpong_LDFLAGS = @RT_LIBS@
xcmpong_LDADD = libxcm.la

if XCM_TOOL
xcm_SOURCES = tools/xcm/main.c tools/xcm/fdfwd.c tools/common/attr.c \
	common/util.c
# You might think of _CFLAGS setting as a no-op, but in fact this
# makes 'common/util.c' to be built in a separate version for
# 'xcm', which is needed since the other version is built by
# libtool.
xcm_CFLAGS = $(AM_CFLAGS)
xcm_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/tools/common -DUT_STD_ASSERT
xcm_LDADD = libxcm.la
xcm_LDFLAGS = @EVENT_LIBS@

xcmrelay_SOURCES = tools/xcmrelay/main.c tools/xcmrelay/rserver.c \
	tools/xcmrelay/xrelay.c tools/common/attr.c common/util.c
# You might think of _CFLAGS setting as a no-op, but in fact this
# makes 'common/util.c' to be built in a separate version for
# 'xcm', which is needed since the other version is built by
# libtool.
xcmrelay_CFLAGS = $(AM_CFLAGS)
xcmrelay_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/tools/common -DUT_STD_ASSERT
xcmrelay_LDADD = libxcm.la
xcmrelay_LDFLAGS = @EVENT_LIBS@
endif

if CTL
xcmctl_SOURCES = tools/xcmctl/main.c common/util.c
xcmctl_CFLAGS = $(AM_CFLAGS)
xcmctl_CPPFLAGS = $(AM_CPPFLAGS) -DUT_STD_ASSERT
xcmctl_LDADD = libxcmctl.la
endif

if EXAMPLES
server_SOURCES = example/server.c
server_CFLAGS = $(AM_CFLAGS)
server_LDADD = libxcm.la

client_SOURCES = example/client.c
client_CFLAGS = $(AM_CFLAGS)
client_LDADD = libxcm.la

echod_SOURCES = example/echod.c
echod_CFLAGS = $(AM_CFLAGS)
echod_LDADD = libxcm.la
echod_LDFLAGS = @EVENT_LIBS@
endif

UTEST_SOURCES = test/src/utest/utest.c  test/src/utest/utestreport.c \
        test/src/utest/utesthumanreport.c
TEST_CPPFLAGS=-I$(srcdir)/test -I$(srcdir)/test/src/utest \
	-I$(srcdir)/libxcm/core -I$(srcdir)/libxcm/tp/common

XCMTEST_TESTCASE_SOURCES = \
	test/src/addr_testcases.c \
	test/src/attr_map_testcases.c \
	test/src/attr_path_testcases.c \
	test/src/attr_tree_testcases.c \
	test/src/slist_testcases.c \
	test/src/xcm_testcases.c

xcmtest_SOURCES = \
	$(XCMTEST_TESTCASE_SOURCES) \
	$(UTEST_SOURCES) \
	libxcm/core/log.c \
	libxcm/core/attr_node.c \
	libxcm/core/attr_path.c \
	libxcm/core/attr_tree.c \
	libxcm/core/log_attr_tree.c \
	common/slist.c \
	common/util.c \
	test/src/iowrap.c \
	test/src/pingpong.c \
	test/src/testutil.c \
	test/src/tnet.c

xcmtest_CPPFLAGS=$(AM_CPPFLAGS) $(TEST_CPPFLAGS) -DUT_STD_ASSERT
xcmtest_LDFLAGS = @RT_LIBS@ @PTHREAD_LIBS@ -ldl -no-install
xcmtest_LDADD = libxcm.la
if CTL
xcmtest_LDADD += libxcmctl.la
endif

doxygen: .doxygenerated

doxygen-pdf:
	make -C doc/latex

.doxygenerated: $(include_HEADERS)
	doxygen doc/doxygen.conf && touch .doxygenerated

clean-local:
	rm -rf doc/html
	rm -rf doc/latex
	rm -f common/*.d libxcm/*.d libxcmc/*.d example/*.d tools/*.d
	rm -f .doxygenerated
	rm -rf test/data

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
LTTNGWRAP=./test/tools/with_lttng.sh
endif

if VALGRIND
xcmtest-run-valgrind: xcmtest
	cmd="$(LTTNGWRAP) valgrind --tool=memcheck --leak-check=full -q --suppressions=./test/src/lttng.supp --suppressions=./test/src/glibc.supp --num-callers=20 --error-exitcode=1 ./xcmtest -v -c"; \
	if [ "`id -u`" = 0 ]; then \
		$$cmd -p 8 $(TESTS); \
	else \
		$$cmd $(TESTS); \
	fi
endif

if PYTHON
xcm_PYTHON=python/xcm.py
xcmdir = $(pythondir)
python-test: libxcm.la
	python3 -m flake8 $(xcm_PYTHON) \
		python/test_xcm.py test/src/test_xcmrelay.py
	LD_LIBRARY_PATH=$(builddir)/.libs \
		$(PYTEST) -vv $(PYTESTOPTS) -s $(PYTESTS)
endif

verify-versioning:
	./test/tools/verify_versioning.py $(srcdir)/include/xcm.h \
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
