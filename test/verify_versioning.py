#!/usr/bin/python

import sys
import re
import os
import stat

if len(sys.argv) != 6:
    print "Usage: %s <xcm-hdr-file> <builddir> <expected-major> " \
        "<expected-minor> <expected-impl-revision>" % sys.argv[0]
    sys.exit(1)

hdr_version_re = re.compile(r'@version\s+([0-9]+)\.([0-9]+)')

def check_hdr(hdr, major, minor):
    hdr = file(xcm_hdr_file).read()

    hdr_m = hdr_version_re.search(hdr)

    print "ABI is version %d.%d." % (major, minor)

    if not hdr_m:
        print "Can't find version info in %s." % xcm_hdr_file
        sys.exit(1)

    hdr_major, hdr_minor = [int(ver) for ver in hdr_m.groups()]

    print "XCM ABI documented to be version %d.%d in \"%s\"." % (hdr_major, hdr_minor, xcm_hdr_file)

    if major != hdr_major:
        print "Incorrect major version in header file."
        sys.exit(1)

    if minor != hdr_minor:
        print "Incorrect minor version in header file."
        sys.exit(1)

def check_so(builddir, major, minor, impl):
    so_file = "%s/.libs/libxcm.so.%d.%d.%d" % (builddir, major, minor, impl)
    st = os.stat(so_file)
    if not stat.S_ISREG(st.st_mode):
        print "Shared library file \"%s\" not found." % so_file
        sys.exit(1)
    else:
        print "Shared library is at \"%s\", as expected." % so_file
        
xcm_hdr_file = sys.argv[1]
builddir = sys.argv[2]
major = int(sys.argv[3])
minor = int(sys.argv[4])
impl = int(sys.argv[5])

check_hdr(xcm_hdr_file, major, minor)

check_so(builddir, major, minor, impl)

print "All good."
sys.exit(0)
