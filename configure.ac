 -*- Autoconf -*-

m4_define([xcm_major_version], [1])
m4_define([xcm_minor_version], [9])
m4_define([xcm_patch_version], [1])
m4_define([xcm_version],[xcm_major_version.xcm_minor_version.xcm_patch_version])

# XCM never had a non-backward-compatible API/ABI change for any
# release, even before version 1.0.0.
m4_define([xcm_abi_major_version], [m4_eval(xcm_major_version - 1)])
# step xcm_minor_version if this is increased
m4_define([xcm_abi_minor_version], 24)
m4_define([xcm_abi_version],[xcm_abi_major_version.xcm_abi_minor_version])

AC_INIT(xcm, [xcm_version], [mattias.ronnblom@ericsson.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([common/config.h])
AC_PREREQ([2.63])
AC_PROG_CC

AC_SUBST([XCM_ABI_MAJOR_VERSION], [xcm_abi_major_version])
AC_SUBST([XCM_ABI_MINOR_VERSION], [xcm_abi_minor_version])
AC_SUBST([XCM_ABI_VERSION], [xcm_abi_version])
AC_SUBST([XCM_MAJOR_VERSION], [xcm_major_version])
AC_SUBST([XCM_MINOR_VERSION], [xcm_minor_version])
AC_SUBST([XCM_PATCH_VERSION], [xcm_patch_version])
AC_SUBST([XCM_VERSION], [xcm_version])

# XCM depends on constructor functions to register transports into the
# core library, and thus cannot be built statically.
AC_DISABLE_STATIC

# Enable late pthread features
AC_USE_SYSTEM_EXTENSIONS

LT_INIT

AC_CHECK_LIB([rt], [clock_gettime],
             [AC_SUBST([RT_LIBS], [-lrt])],
             [AC_MSG_ERROR([Unable to find the RT library.])])
AC_CHECK_LIB([pthread], [pthread_create],
             [AC_SUBST([PTHREAD_LIBS], [-lpthread])],
             [AC_MSG_ERROR([Unable to find the pthread library.])])

AC_SUBST([AM_CFLAGS])

AC_CONFIG_FILES([Makefile include/xcm_version.h python/config.py])

AC_ARG_ENABLE([cares],
    AS_HELP_STRING([--disable-cares], [use glibc resolver instead of the c-ares library]))

AS_IF([test "x$enable_cares" != "xno"], [
	AC_CHECK_LIB([cares], [ares_init],
	             [AC_SUBST([CARES_LIBS], [-lcares])],
	             [AC_MSG_ERROR([Unable to find the c-ares DNS library.])])
	AC_CHECK_HEADERS(ares.h, [:],
	                 [AC_MSG_ERROR([Unable to find c-ares header file.])])
	AC_PREPROC_IFELSE([AC_LANG_PROGRAM([#include <ares.h>],
	                                   [
#if ARES_VERSION < 0x11000
#error c-ares version must be at least 1.16.0
#endif
                                           ])],
                          [AC_MSG_RESULT(yes)],
                          [AC_MSG_FAILURE([c-ares 1.16.0 or later is required.])])
	AC_DEFINE([XCM_CARES], [1], [Use c-ares DNS library.])
	AC_SUBST(XCM_CARES, 1)], [
	AC_CHECK_LIB([anl], [getaddrinfo_a],
	             [AC_SUBST([ANL_LIBS], [-lanl])],
	             [AC_MSG_ERROR([Unable to find the ANL library.])])
	]
)

AM_CONDITIONAL([CARES], [test "x$enable_cares" != "xno"])

AC_ARG_ENABLE([tls],
    AS_HELP_STRING([--disable-tls], [disable XCM TLS and UTLS transports]))

AS_IF([test "x$enable_tls" != "xno"], [
	AC_CHECK_LIB(crypto, CRYPTO_memdup, [:],
		    [AC_MSG_ERROR([Unable to find the Crypto library.])])
	AC_CHECK_LIB(ssl, SSL_write, [AC_SUBST([SSL_LIBS], [-lssl])],
		    [AC_MSG_ERROR([Unable to find the OpenSSL library.])])
	AC_CHECK_HEADERS(openssl/ssl.h, [:],
                 [AC_MSG_ERROR([Unable to find the OpenSSL header files.])])
	AC_CHECK_DECLS([OPENSSL_THREADS], [],
	               [AC_MSG_ERROR([OpenSSL is built w/o threads support.])],
		       [#include <openssl/ssl.h>])
	AC_MSG_CHECKING([OpenSSL version])
	AC_PREPROC_IFELSE([AC_LANG_PROGRAM([#include <openssl/opensslv.h>],
	                                   [
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error OpenSSL version is not recent enough
#endif
                                           ])],
                          [AC_MSG_RESULT(yes)],
                          [AC_MSG_FAILURE([OpenSSL 1.1.x or later is required])])
	AC_DEFINE([XCM_TLS], [1], [XCM TLS and UTLS Transports.])
	AC_SUBST(XCM_TLS, 1)
])

AM_CONDITIONAL([TLS], [test "x$enable_tls" != "xno"])

AC_ARG_ENABLE([sctp],
    AS_HELP_STRING([--enable-sctp], [enable XCM SCTP transport]))

AS_IF([test "x$enable_sctp" = "xyes"], [
	AC_CHECK_HEADERS(netinet/sctp.h, [],
                 [AC_MSG_ERROR([Unable to find the SCTP header files.])])
	AC_DEFINE([XCM_SCTP], [1], [XCM SCTP Transports.])
])

AM_CONDITIONAL([SCTP], [test "x$enable_sctp" = "xyes"])

AC_ARG_ENABLE([xcm_tool],
    AS_HELP_STRING([--disable-xcm-tool], [disable the 'xcm' command-line tool]))

AS_IF([test "x$enable_xcm_tool" != "xno"], [
	AC_CHECK_LIB(event, event_base_dispatch,
	             [AC_SUBST([EVENT_LIBS], [-levent])],
	             [AC_MSG_ERROR([Unable to find the libevent library. Disable the XCM tool to avoid this dependency.])])
	AC_CHECK_HEADERS(event.h, [:],
	                 [AC_MSG_ERROR([Unable to find libevent header files.])])
])

AM_CONDITIONAL([XCM_TOOL], [test "x$enable_xcm_tool" != "xno"])

AC_ARG_ENABLE([lttng],
    AS_HELP_STRING([--disable-lttng], [disable LTTNG logging support]))

AM_CONDITIONAL([LTTNG], [test "x$enable_lttng" != "xno"])

AS_IF([test "x$enable_lttng" != "xno"], [
	AC_CHECK_LIB([lttng-ust], [main],
	             [AC_SUBST([LTTNG_LIBS], [-llttng-ust])],
	             [AC_MSG_ERROR([Unable to find the lttng-ust library. Disable LTTng to avoid this dependency.])])
])

AC_ARG_ENABLE([ctl],
    AS_HELP_STRING([--disable-ctl], [disable XCM control interface]))

AM_CONDITIONAL([CTL], [test "x$enable_ctl" != "xno"])

AS_IF([test "x$enable_ctl" != "xno"], [
	AC_DEFINE([XCM_CTL], [1], [XCM Control interface.])
])

AC_ARG_ENABLE([python],
    AS_HELP_STRING([--disable-python], [disable Python XCM interface]))

AM_CONDITIONAL([PYTHON], [test "x$enable_python" != "xno"])

AS_IF([test "x$enable_python" != "xno"], [AM_PATH_PYTHON])

AC_ARG_ENABLE([valgrind],
    AS_HELP_STRING([--enable-valgrind], [use Valgrind when running tests]))

AS_IF([test "x$enable_valgrind" = "xyes"], [
	AC_CHECK_PROG(valgrind, [],
                 [AC_MSG_ERROR([Unable to find Valgrind executable.])])
])

AM_CONDITIONAL([VALGRIND], [test "x$enable_valgrind" = "xyes"])

AC_OUTPUT
