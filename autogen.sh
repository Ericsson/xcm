#! /bin/sh

autoheader && \
libtoolize && \
aclocal && \
automake --add-missing && \
autoconf
