# shell script version of the utest test framework

tests_ok=0
tests_failed=0

utest_running() {
    echo -n "$1: "
}

utest_ok() {
    tests_ok=`echo $tests_ok + 1 | bc`
    echo OK
}

utest_fail() {
    tests_failed=`echo $tests_failed + 1 | bc`
    echo FAILED
}

utest_run() {
    for t in $*; do
	utest_running $t
	if $t; then
	    utest_ok
	else
	    utest_fail
	fi
    done
}

utest_report() {
    echo "`echo $tests_failed + $tests_ok | bc` tests run; $tests_ok successes and $tests_failed failures."
    if [ "$tests_failed" -eq 0 ]; then
	return 0
    else
	return 1
    fi
}   

utest_chk() {
    if [ "$#" -eq 2 -a "$1" = "$2" ]; then
	utest_ok
    else
	utest_fail
    fi
}

utest_chknoerr() {
    if [ "$?" = 0 ]; then
	utest_ok
    else
	utest_fail
    fi
}

