#!/usr/bin/python3

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Ericsson AB

import sys
import re
import os
import stat

if len(sys.argv) != 9:
    print("Usage: %s <xcm-hdr-file> <readme> <builddir> <expected-abi-major> "
          "<expected-abi-minor> <expected-impl-major>"
          "<exepected-impl-minor> <expected-impl-patch>" % sys.argv[0])
    sys.exit(1)

hdr_abi_version_re = \
    re.compile(r'@version\s+([0-9]+)\.([0-9]+).*API.*')
hdr_impl_version_re = \
    re.compile(r'@version\s+([0-9]+)\.([0-9]+)\.([0-9]+).*Implementation.*')

readme_link_re = re.compile(r'xcm/api/([0-9]+)\.([0-9]+)/')

def check_hdr(hdr_file, abi_major, abi_minor, impl_major, impl_minor,
              impl_patch):
    hdr = open(hdr_file).read()

    print("ABI version: %d.%d." % (abi_major, abi_minor))
    print("Implementation version: %d.%d.%d" %
          (impl_major, impl_minor, impl_patch))
    print("Header file: %s" % hdr_file)

    hdr_abi_m = hdr_abi_version_re.search(hdr)
    if not hdr_abi_m:
        print("Can't find ABI version info in %s." % hdr_file)
        sys.exit(1)
    hdr_abi_major, hdr_abi_minor = [int(ver) for ver in hdr_abi_m.groups()]

    print("Pathfinder ABI documented to be version %d.%d." %
          (hdr_abi_major, hdr_abi_minor))

    if abi_major != hdr_abi_major:
        print("Incorrect ABI major version in header file.")
        sys.exit(1)

    if abi_minor != hdr_abi_minor:
        print("Incorrect ABI minor version in header file.")
        sys.exit(1)

    hdr_impl_m = hdr_impl_version_re.search(hdr)
    if not hdr_impl_m:
        print("Can't find Implementation version info in %s." % hdr_file)
        sys.exit(1)
    hdr_impl_major, hdr_impl_minor, hdr_impl_patch = \
        [int(ver) for ver in hdr_impl_m.groups()]

    print("Pathfinder library implementation documented to be "
          "version %d.%d.%d." % (hdr_impl_major, hdr_impl_minor,
                                 hdr_impl_patch))

    if impl_major != hdr_impl_major:
        print("Incorrect implementation major version in header file.")
        sys.exit(1)

    if impl_minor != hdr_impl_minor:
        print("Incorrect implementation minor version in header file.")
        sys.exit(1)

    if impl_patch != hdr_impl_patch:
        print("Incorrect implementation patch version in header file.")
        sys.exit(1)

def check_readme(readme_file, abi_major, abi_minor):
    readme = open(readme_file).read()

    readme_m = readme_link_re.search(readme)

    if not readme_m:
        print("Can't find API documentation link in %s." % readme_file)
        sys.exit(1)

    readme_abi_major, readme_abi_minor = [int(ver) for ver in readme_m.groups()]

    print("README documentation link points towards version %d.%d." %
          (readme_abi_major, readme_abi_minor))

    if abi_major != readme_abi_major:
        print("Incorrect ABI major version in link.")
        sys.exit(1)

    if abi_minor != readme_abi_minor:
        print("Incorrect ABI minor version in link.")
        sys.exit(1)

def check_so(builddir, abi_major, abi_minor):
    so_file = "%s/.libs/libxcm.so.%d.%d.0" % \
        (builddir, abi_major, abi_minor)
    try:
        st = os.stat(so_file)
        if stat.S_ISREG(st.st_mode):
            print("Shared library file is at \"%s\", as expected." % so_file)
        else:
            print("\"%s\" is not a regular file." % so_file)
            sys.exit(1)
    except FileNotFoundError:
            print("Shared library file \"%s\" not found." % so_file)
            sys.exit(1)
        
xcm_hdr_file = sys.argv[1]
readme = sys.argv[2]
builddir = sys.argv[3]
abi_major = int(sys.argv[4])
abi_minor = int(sys.argv[5])
impl_major = int(sys.argv[6])
impl_minor = int(sys.argv[7])
impl_patch = int(sys.argv[8])

check_hdr(xcm_hdr_file, abi_major, abi_minor, impl_major, impl_minor,
          impl_patch)

check_readme(readme, abi_major, abi_minor)

check_so(builddir, abi_major, abi_minor)

print("All good.")
sys.exit(0)
