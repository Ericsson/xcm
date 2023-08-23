#!/usr/bin/python3

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Ericsson AB

#
# check-release.py -- script to verify XCM release before pushing
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Ericsson AB
#

import getopt
import git
import os
import re
import subprocess
import sys
import tempfile

from functools import total_ordering


def usage(name):
    print("%s [-c <cmd>] <release-sha|release-tag>" % name)
    print("Options:")
    print("  -c <cmd>  Run command <cmd>. Default is to run all.")
    print("  -m        Enable valgrind in the test suite.")
    print("  -h        Print this text.")
    print("Commands:")
    print("  meta     Only check release meta data.")
    print("  abi      Check ABI against the previous release.")
    print("  changes  Only list changes with previous release.")
    print("  test     Only run the test suites.")


def prefix(msg, *args):
    print("%s: " % msg, end="")
    print(*args, end="")
    print(".")


def fail(*args):
    prefix("ERROR", *args)
    sys.exit(1)


def note(*args):
    prefix("NOTE", *args)


@total_ordering
class Version:
    def __init__(self, major, minor, patch=None):
        self.major = major
        self.minor = minor
        self.patch = patch

    def __str__(self):
        s = "%d.%d" % (self.major, self.minor)
        if self.patch is not None:
            s += ".%d" % self.patch
        return s

    def __lt__(self, other):
        if self.major == other.major:
            if self.minor == other.minor:
                if self.patch is None:
                    assert other.patch is None
                    return False
                return self.patch < other.patch
            return self.minor < other.minor
        else:
            return self.major < other.major

    def __eq__(self, other):
        if self.major != other.major or  \
           self.minor != other.minor:
            return False
        if self.patch is None:
            return other.patch is None
        else:
            if other.patch is None:
                return False
            return self.patch == other.patch


api_re = re.compile(r'@version (0)\.([0-9]+) \[API\]')
impl_re = re.compile(r'@version (1)\.([0-9]+)\.([0-9]+) \[Implementation\]')


def hdr_get_version(version_name, version_re, commit):
    hdrobj = commit.tree / 'include/xcm.h'
    hdr = hdrobj.data_stream.read().decode('utf-8')
    m = version_re.search(hdr)
    if m is None:
        fail("%s version not found in XCM header file." % version_name)
    major = int(m.groups()[0])
    minor = int(m.groups()[1])
    if len(m.groups()) == 3:
        patch = int(m.groups()[2])
    else:
        patch = None
    return Version(major, minor, patch)


def hdr_get_api_version(commit):
    return hdr_get_version('API', api_re, commit)


def hdr_get_impl_version(commit):
    return hdr_get_version('Implementation', impl_re, commit)


def get_release_tags(repo):
    return [t for t in repo.tags if tag_re.match(t.name)]


def get_commit_release_tags(repo, commit):
    return [tag for tag in get_release_tags(repo) if tag.commit == commit]


def get_commit_release_tag(repo, commit):
    tags = get_commit_release_tags(repo, commit)

    if len(tags) != 1:
        fail("Could not find exactly one release tag for commit %s" %
             release_commit)

    return tags[0]


def get_release_versions(repo):
    return [tag_version(tag) for tag in get_release_tags(repo)]


def get_prev_release_tag(repo, release_version):

    release_tags = get_release_tags(repo)

    candidate = None

    for tag in release_tags[1:]:
        v = tag_version(tag)

        if v.major != release_version.major or \
           v.minor > release_version.minor:
            continue

        if v.minor == release_version.minor and \
           v.patch >= release_version.patch:
            continue

        if candidate is None:
            candidate = tag
            continue

        candidate_v = tag_version(candidate)
        if v.minor > candidate_v.minor:
            candidate = tag
            continue

        if v.minor == candidate_v.minor and v.patch > candidate_v.patch:
            candidate = tag
            continue

    if candidate is None:
        fail("Unable to find the release previous to %s" % release_version)

    return candidate


tag_re = re.compile('^v[0-9]+')


def tag_name(impl_version):
    return "v%s" % impl_version


def tag_version(tag):
    assert tag.name[0] == 'v'
    v = tag.name[1:].split('.')
    major = int(v[0])
    minor = int(v[1])
    patch = int(v[2])
    return Version(major, minor, patch)


def validate_against_prev(this_api_version, this_impl_version,
                          prev_api_version, prev_impl_version):
    if prev_api_version > this_api_version:
        fail("Previous release %s has higher API/ABI version %s." %
             prev_api_version, this_api_version)

    assert this_api_version.major == prev_api_version.major
    assert this_impl_version.major == prev_impl_version.major

    new_api = this_api_version > prev_api_version
    bumped_impl_minor = this_impl_version.minor > prev_impl_version.minor

    if new_api and not bumped_impl_minor:
        fail("New API but minor version not bumped")
    elif not new_api and bumped_impl_minor:
        note("Minor version is increased, although API version "
             "remains unchanged")

    if this_impl_version.minor == prev_impl_version.minor:
        note("This is a maintenance release")
    else:
        minor_diff = this_impl_version.minor - prev_impl_version.minor
        if minor_diff != 1:
            note("Minor releases are skipped in between %s and %s" %
                 (prev_impl_version, this_impl_version))

        api_diff = this_api_version.minor - prev_api_version.minor
        if api_diff != 1:
            note("API/ABI versions are skipped between %s and %s" %
                 (prev_api_version, this_api_version))


def check_meta(repo, release_commit):
    release_tag = get_commit_release_tag(repo, release_commit)

    api_version = hdr_get_api_version(release_commit)
    impl_version = hdr_get_impl_version(release_commit)
    tag_impl_version = tag_version(release_tag)

    if tag_impl_version != impl_version:
        fail("Version according to tag and according to <xcm.h> differ")

    prev_release_tag = get_prev_release_tag(repo, impl_version)
    prev_api_version = hdr_get_api_version(prev_release_tag.commit)
    prev_impl_version = hdr_get_impl_version(prev_release_tag.commit)

    print("Release information:")
    print("  API version (from <xcm.h>): %s" % api_version)
    print("  Implementation version (from <xcm.h>): %s" % impl_version)
    print("  Implementation version (from tag): %s" % tag_impl_version)
    print("  Commit:")
    print("    SHA: %s" % release_commit.hexsha)
    print("    Summary: %s" % release_commit.summary)
    print("  Previous release: %s (API %s)" % (prev_impl_version,
                                               prev_api_version))
    print("Releases:")
    for version in get_release_versions(repo):
        print("  %s" % version)

    validate_against_prev(api_version, impl_version,
                          prev_api_version, prev_impl_version)


def check_abi(repo, release_commit):
    release_tag = get_commit_release_tag(repo, release_commit)

    prev_release_tag = get_prev_release_tag(repo, tag_version(release_tag))
    prev_release_commit = prev_release_tag.object

    conf = ""

    temp_dir = tempfile.TemporaryDirectory()
    cmd = build_cmd(conf, EXTRA_ABI_CFLAGS, release_commit, release_tag,
                    temp_dir.name)
    run(cmd)

    prev_temp_dir = tempfile.TemporaryDirectory()
    prev_cmd = build_cmd(conf, EXTRA_ABI_CFLAGS, prev_release_commit,
                         prev_release_tag, prev_temp_dir.name)
    run(prev_cmd)

    version = tag_version(release_tag)
    prev_version = tag_version(prev_release_tag)

    so_file = "%s/xcm-%s/.libs/libxcm.so" % (temp_dir.name, version)
    prev_so_file = "%s/xcm-%s/.libs/libxcm.so" % \
        (prev_temp_dir.name, prev_version)

    hdr_dir = "%s/xcm-%s/include" % (temp_dir.name, version)
    prev_hdr_dir = "%s/xcm-%s/include" % (prev_temp_dir.name, prev_version)

    abidiff = "abidiff --hf1 %s --hf2 %s %s %s" % \
        (prev_hdr_dir, hdr_dir, prev_so_file, so_file)

    has_abi_changes = run(abidiff, exit_on_error=False)

    expect_abi_changes = version.minor != prev_version.minor or \
        version.major != prev_version.major

    if expect_abi_changes and not has_abi_changes:
        note("Minor release increase, although no ABI changes detected")
    elif not expect_abi_changes and has_abi_changes:
        fail("ABI changes detected, while version numbering suggests "
              "otherwise")

    temp_dir.cleanup()
    prev_temp_dir.cleanup()


def check_changes(repo, release_commit):
    release_tag = get_commit_release_tag(repo, release_commit)

    prev_release_tag = get_prev_release_tag(repo, tag_version(release_tag))

    rev = '%s..%s' % (prev_release_tag, release_tag)

    print("Changes between %s and %s:" % (tag_version(prev_release_tag),
                                          tag_version(release_tag)))
    for commit in repo.iter_commits(rev=rev):
        short_sha = repo.git.rev_parse(commit, short=True)
        print(" %s %s" % (short_sha, commit.summary))


def run(cmd, exit_on_error=True):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, encoding='utf-8')

    if res.returncode != 0:
        sys.stderr.write(res.stdout)
        if exit_on_error:
            sys.exit(1)
        else:
            return True
    return False


def assure_sudo():
    subprocess.run("sudo echo -n", shell=True, check=True)


def test_build_separate_build_dir(repo, release_commit):
    release_tag = get_commit_release_tag(repo, release_commit)

    print("Test build w/ separate build directory.")
    cmd = """
set -e
tmpdir=`mktemp -d`; \\
xcmdir=xcm-%s; \\
tarfile=$tmpdir/$xcmdir.tar; \\
git archive --prefix=$xcmdir/ --format=tar -o $tarfile %s; \\
cd $tmpdir; \\
tar xf $tarfile; \\
cd $xcmdir; \\
autoreconf -i; \\
mkdir build; \\
cd build; \\
../configure; \\
make -j; \\
""" % (tag_version(release_tag), release_commit)

    run(cmd)


EXTRA_BUILD_CFLAGS="-Werror"

# to make more old releases build
EXTRA_ABI_CFLAGS="-Wno-error"

def build_cmd(conf, cflags, release_commit, release_tag, build_dir):
    env_cflags = os.environ.get('CFLAGS')
    if env_cflags is not None:
        cflags += (" %s" % env_cflags)

    conf += (" CFLAGS=\"%s\"" % cflags)

    return """
set -e
tmpdir=%s; \\
xcmdir=xcm-%s; \\
tarfile=$tmpdir/$xcmdir.tar; \\
git archive --prefix=$xcmdir/ --format=tar -o $tarfile %s;\\
cd $tmpdir; \\
tar xf $tarfile; \\
cd $xcmdir; \\
autoreconf -i; \\
./configure %s; \\
make -j; \\
make doxygen; \\
""" % (build_dir, tag_version(release_tag), release_commit, conf)


def run_test(repo, conf, release_commit, use_valgrind):
    release_tag = get_commit_release_tag(repo, release_commit)

    if use_valgrind:
        conf += " --enable-valgrind"

    print("Running test ", end="")
    if conf == "":
        print("using default configure options.")
    else:
        print("using configure options: \"%s\"." % conf)

    temp_dir = tempfile.TemporaryDirectory()

    cmd = build_cmd(conf, EXTRA_BUILD_CFLAGS, release_commit, release_tag,
                    temp_dir.name)

    cmd += """
make check; \\
sudo make check \\
"""

    run(cmd)

    temp_dir.cleanup()

def run_tests(repo, release_commit, use_valgrind):
    assure_sudo()

    test_build_separate_build_dir(repo, release_commit)

    for conf in ("", "--disable-tls --disable-ctl --disable-lttng"):
        run_test(repo, conf, release_commit, use_valgrind)


def check_repo(repo):
    if repo.is_dirty():
        fail("Repository contains modifications.")


optlist, args = getopt.getopt(sys.argv[1:], 'c:mh')

cmd = None
use_valgrind = False

for opt, optval in optlist:
    if opt == '-h':
        usage(sys.argv[0])
        sys.exit(0)
    if opt == '-c':
        cmd = optval
    if opt == '-m':
        use_valgrind = True

if len(args) != 1:
    usage(sys.argv[0])
    sys.exit(1)

repo = git.Repo()
check_repo(repo)

release_commit = repo.commit(args[0])

meta = False
changes = False
test = False
abi = False

if cmd == 'meta':
    meta = True
elif cmd == 'changes':
    changes = True
elif cmd == 'abi':
    abi = True
elif cmd == 'test':
    test = True
elif cmd is None:
    meta = True
    changes = True
    abi = True
    test = True
else:
    print("Unknown cmd '%s'." % cmd)
    sys.exit(1)

if meta:
    check_meta(repo, release_commit)
if changes:
    check_changes(repo, release_commit)
if abi:
    check_abi(repo, release_commit)
if test:
    run_tests(repo, release_commit, use_valgrind)
