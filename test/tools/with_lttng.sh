#!/bin/bash

fail() {
    echo "$1" &2>1
    exit 1
}

if [ -n "`pidof lttng-sessiond`" ]; then
    lttng-sessiond --daemonize
fi

SESSION=xcmtest-$$

lttng create $SESSION || fail "Unable to create LTTng session $SESSION."
lttng enable-event --userspace 'com_ericsson_xcm:*' || \
    fail "Unable to enable XCM LTTng event."
lttng start || fail "Unable to start LTTng."
$*
ec=$?
lttng stop || fail "Unable to stop LTTng."
lttng destroy $SESSION || fail "Unable to destroy LTTng session $SESSION."
exit $ec

