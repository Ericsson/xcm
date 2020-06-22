#!/bin/bash

set -o pipefail

run_check() {
    ./configure $* && \
	make clean && \
	make && \
	make xcmtest && \
	sudo make check && \
	make clean
    if [ $? -ne 0 ]; then
	echo "Failure in build/test with options: $*"
        exit 1
    else
	echo "Successfully built/tested with options: $*"
    fi
}

./autogen.sh

# not all combinations - but the ones deemed most common
run_check
run_check --disable-tls
run_check --disable-lttng
run_check --disable-tls --disable-lttng
run_check --disable-xcm-tool
run_check --disable-ctl
run_check --disable-python
run_check --disable-python --disable-tls
run_check --enable-sctp
