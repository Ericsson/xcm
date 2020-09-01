#!/usr/bin/python

import sys
import re
import os
import stat

if len(sys.argv) != 7:
    print "Usage: %s <xcm-hdr-file> <readme> <builddir> <expected-major> " \
        "<expected-minor> <expected-impl-revision>" % sys.argv[0]
    sys.exit(1)

hdr_version_re = re.compile(r'@version\s+([0-9]+)\.([0-9]+)')

readme_link_re = re.compile(r'xcm/api/([0-9]+)\.([0-9]+)/')

def check_hdr(hdr_file, major, minor):
    hdr = file(hdr_file).read()

    hdr_m = hdr_version_re.search(hdr)

    print "ABI is version %d.%d." % (major, minor)

    if not hdr_m:
        print "Can't find version info in %s." % hdr_file
        sys.exit(1)

    hdr_major, hdr_minor = [int(ver) for ver in hdr_m.groups()]

    print "XCM ABI documented to be version %d.%d in \"%s\"." % \
        (hdr_major, hdr_minor, hdr_file)

    if major != hdr_major:
        print "Incorrect major version in header file."
        sys.exit(1)

    if minor != hdr_minor:
        print "Incorrect minor version in header file."
        sys.exit(1)

def check_readme(readme_file, major, minor):
    readme = file(readme_file).read()

    readme_m = readme_link_re.search(readme)

    if not readme_m:
        print "Can't find API documentation link in %s." % readme_file
        sys.exit(1)

    readme_major, readme_minor = [int(ver) for ver in readme_m.groups()]

    print "README link points towards version %d.%d." % \
        (readme_major, readme_minor)

    if major != readme_major:
        print "Incorrect major version in link."
        sys.exit(1)

    if minor != readme_minor:
        print "Incorrect minor version in link."
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
readme = sys.argv[2]
builddir = sys.argv[3]
major = int(sys.argv[4])
minor = int(sys.argv[5])
impl = int(sys.argv[6])

check_hdr(xcm_hdr_file, major, minor)

check_readme(readme, major, minor)

check_so(builddir, major, minor, impl)

print "All good."
sys.exit(0)
