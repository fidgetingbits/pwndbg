from __future__ import annotations

import gdb
import pytest

import pwndbg

# There is known redundancy between tests because as part of porting
# libslub I want to ensure that I have one to one functionality between
# importing the library manually, and running it inside of pwndbg

# Test ideas:
# - test cache listing on multi cpu systems
# - we could do way more intelligent parsing of slab output, like correlating
#   that the lockless free list counts corresponds the number of elements shown, etc

# TODO:
# - Missing --cmds


def test_command_slab_list():
    if not pwndbg.gdblib.kernel.has_debug_syms():
        res = gdb.execute("slab list", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("slab list", to_string=True)
    assert "kmalloc" in res


def test_command_slab_info():
    if not pwndbg.gdblib.kernel.has_debug_syms():
        res = gdb.execute("slab info kmalloc-512", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    for cache in pwndbg.gdblib.kernel.slab.caches():
        cache_name = cache.name
        res = gdb.execute(f"slab info -v {cache_name}", to_string=True)
        assert cache_name in res
        assert "Freelist" in res
        for cpu in range(pwndbg.gdblib.kernel.nproc()):
            assert f"[CPU {cpu}]" in res

    res = gdb.execute("slab info -v does_not_exit", to_string=True)
    assert "not found" in res


def test_command_slab_contains():
    if not pwndbg.gdblib.kernel.has_debug_syms():
        res = gdb.execute("slab contains 0x123", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    # retrieve a valid slab object address (first address from freelist)
    addr, slab_cache = get_slab_object_address()

    res = gdb.execute(f"slab contains {addr}", to_string=True)
    assert f"{addr} @ {slab_cache}" in res


def get_slab_object_address():
    """helper function to get the address of some kmalloc slab object
    and the associated slab cache name"""
    import re

    caches = pwndbg.gdblib.kernel.slab.caches()
    for cache in caches:
        cache_name = cache.name
        info = gdb.execute(f"slab info -v {cache_name}", to_string=True)
        matches = re.findall(r"- (0x[0-9a-fA-F]+)", info)
        if len(matches) > 0:
            return (matches[0], cache_name)
    raise ValueError("Could not find any slab objects")


def libslub_exists(cmd, subcmd):
    """Make sure that libslub script was actually loaded into the image correctly"""

    try:
        res = gdb.execute(cmd, to_string=True)
        assert subcmd in res
    except gdb.error:
        assert False, "libslub was not loaded into the image correctly"


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_exists():
    """Make sure that external libslub script was actually loaded into the image correctly"""

    libslub_exists("sbhelp", "sbcache")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_exists():
    """Make sure that builtin pwndbg libslub command is available"""

    libslub_exists("pwndbg", "slubcache")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_double_call():
    """Make sure that there's no weird bugs with Slub object initialization"""

    for _ in range(2):
        try:
            libslub_exists("sblist", "Legend")
        except gdb.error:
            assert False, "libslub commands failed while being called twice in a row"


def run_slub_list(cmd):
    """Make sure slub listing works for all caches"""
    res = gdb.execute(cmd, to_string=True)

    assert "kmalloc" in res
    count = 0
    for line in res.splitlines():
        if "slab cache name" in line:
            count += 1
    assert count == 1


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_list():
    """Make sure internal slub listing works"""

    run_slub_list("slublist")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slub_list():
    """Make sure external slab listing works"""

    run_slub_list("sblist")


def run_slab_cache_basic(cmd):
    """Make sure slab cache listing works for all caches"""
    # Make sure there are no slab caches we can't parse
    for cache in pwndbg.gdblib.kernel.slab.caches():
        cache_name = cache.name
        res = gdb.execute(f"{cmd} -n {cache_name}", to_string=True)
        assert cache_name in res
        assert "partial" in res
        # There is a risk the cache actually went away, so need to adapt
        if "not found" in res or "(cpu " not in res:
            continue
        for cpu in range(pwndbg.gdblib.kernel.nproc()):
            assert f"(cpu {cpu})" in res

    res = gdb.execute("sbcache -n does_not_exit", to_string=True)
    assert "Wrong slab cache name specified" in res

    # Make sure all of the expected output is present
    # NOTE: Because currently the printing uses colored output, we can't always
    # easily find the data so using simple for now
    res = gdb.execute(f"sbcache --cpu 0 -n kmalloc-8", to_string=True)
    assert "kmem_cache_cpu" in res
    assert "freelist" in res
    assert "frozen" in res
    assert "objects" in res
    assert "(512 elements)" in res

    # TODO: Exhaustively test all arguments


def run_slab_cache_complex(cmd):
    """Test all options for slab cache listing

    This isn't currently exhaustive, but I try to use sane combinations"""

    cache = "kmalloc-2k"
    res = gdb.execute(f"{cmd} -n {cache} --cpu 0 --main-slab --show-region", to_string=True)
    assert "struct page @" in res
    assert "(region start)" in res
    assert "(region end)" in res

    # res = gdb.execute(f"{cmd} -n {cache} --cpu 0 --partial-slab --show-region", to_string=True)
    # assert "struct page @" in res
    # assert "(region start)" in res
    # assert "(region end)" in res

    # Unless we spray, we can't be sure it finds a full one, so just make sure
    # it has any output
    res = gdb.execute(f"{cmd} -n {cache} --cpu 0 --partial-slab --show-region", to_string=True)
    assert cache in res
    assert "offset" in res
    assert "object_size" in res

    res = gdb.execute(f"{cmd} -n {cache} --cpu 0 --show-freelist --show-region", to_string=True)
    assert "freelist = " in res
    assert "region" in res

    res = gdb.execute(f"{cmd} -n {cache} --cpu 0 --show-lockless-freelist", to_string=True)
    assert "freelist = " in res
    assert "region" in res

    res = gdb.execute(
        f"{cmd} -n {cache} --cpu 0 --show-lockless-freelist --object-only", to_string=True
    )
    assert "lockless freelist:" in res


def run_slub_cache_cache(cache_cmd):
    all_caches = gdb.execute(f"{cache_cmd}", to_string=True)
    all_caches_cached = gdb.execute(f"{cache_cmd} --use-cache", to_string=True)
    # Non-cached has some extra stuff about timing and warnings, so we can't
    # direct compare
    for line in all_caches_cached.splitlines():
        assert line in all_caches


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slab_cache():
    """Make sure external slab cache listing works for all caches"""
    cmd = "sbcache"
    run_slab_cache_basic(cmd)
    run_slab_cache_complex(cmd)
    run_slub_cache_cache(cmd)


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slab_cache():
    """Make sure external slab cache listing works for all caches"""
    cmd = "slubcache"
    run_slab_cache_basic(cmd)
    run_slab_cache_complex(cmd)
    run_slub_cache_cache(cmd)


def run_help_arg(cmd_list):
    for cmd in cmd_list:
        res = gdb.execute(f"{cmd} -h", to_string=True)
        assert "usage:" in res


pwndbg_internal_slub_cmd_list = [
    "slublist",
    "slubcache",
    "slubobject",
    "slubmeta",
    "slubdb",
    "slubtrace",
    "slubwatch",
    "slubtrace",
    "slubbreak",
]
pwndbg_external_slub_cmd_list = [
    "sblist",
    "sbcache",
    "sbobject",
    "sbmeta",
    "sbslabdb",
    "sbtrace",
    "sbwatch",
    "sbtrace",
    "sbbreak",
]


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_help():
    """Make sure internal slub cache listing works for all caches"""

    run_help_arg(pwndbg_internal_slub_cmd_list)


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_help():
    """Make sure external slub cache listing works for all caches"""

    run_help_arg(pwndbg_external_slub_cmd_list)


def get_first_slub_object_address(cache_cmd, cache_name):
    res = gdb.execute(f"{cache_cmd} -n {cache_name} --cpu 0 --show-region", to_string=True)
    chunk = None
    for line in res.splitlines():
        if "(region start)" in line:
            chunk = line.split()[0].strip()
            break
    return chunk


# TODO: I don't know if we want to break this into a whole bunch of smaller tests
def slub_object_basic(cache_cmd, obj_cmd):
    cache_name = "kmalloc-256"
    chunk = get_first_slub_object_address(cache_cmd, cache_name)
    assert chunk is not None

    # We expect the chunk address to be printed
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk}", to_string=True)
    assert chunk in res

    # We expect four chunks to be printed
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c 4", to_string=True)
    assert len(res.splitlines()) == 4

    # We expect chunks to be printed until the end of the region
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c unlimited", to_string=True)
    assert "Stopping due to end of memory region" in res

    # We expect their to be hexdump output
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -x", to_string=True)
    assert "bytes of object data" in res
    assert f"{chunk}" in res

    # We should get a warning about walking past the start of the region
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c -2", to_string=True)
    assert "Reaching beginning of memory region" in res

    # We should only see one line containing 16 dash only bytes of hex dump
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c 1 -m 16 -x", to_string=True)
    assert len(res.splitlines()) == 3

    # We should see one of the lines containing * indicating highlighting
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c 4 -H {chunk}", to_string=True)
    assert f"* {chunk}" in res

    # Make sure highlighting a specific allocation type works
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c 4", to_string=True)
    mcount = 0
    fcount = 0
    for line in res.splitlines():
        if line.split()[1] == "M":
            mcount += 1
        elif line.split()[1] == "F":
            fcount += 1
    if mcount > 0:
        highlight = "M"
        hcount = mcount
    else:
        highlight = "F"
        hcount = fcount
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c 4 -I {highlight}", to_string=True)
    found = 0
    for line in res.splitlines():
        if line.startswith("*"):
            found += 1
    assert found == hcount

    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} --object-info", to_string=True)
    assert f"{chunk}" in res

    # Probably a better way to test --cmds work...
    res = gdb.execute(
        f'{obj_cmd} -n {cache_name} {chunk} --cmd "printf \\"rax: 0x%x\\", $rax"', to_string=True
    )
    assert len(res.splitlines()) == 2
    assert "rax: 0x" in res

    # TODO: Need sbobject with -v


def slub_object_highlights(cache_cmd, obj_cmd, meta_cmd):
    cache_name = "kmalloc-256"
    chunk = get_first_slub_object_address(cache_cmd, cache_name)
    assert chunk is not None

    # Mark the first chunk with a tag
    res = gdb.execute(f"{meta_cmd} add {chunk} tag TESTTAG", to_string=True)

    # Check listing with sboject has the tag
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -c 4 -M tag -G TESTTAG", to_string=True)
    assert "TESTTAG" in res
    for line in res.splitlines():
        if line.startswith("*"):
            assert "TESTTAG" in line

    # Check --highlight-only limits the same results above
    res = gdb.execute(
        f"{obj_cmd} -n {cache_name} {chunk} -c 4 -M tag -G TESTTAG --highlight-only", to_string=True
    )
    assert "TESTTAG" in res
    for line in res.splitlines():
        if line.startswith("*"):
            assert "TESTTAG" in line
    # 2 because we expect it to say "Stopping due to end of memory region"
    assert len(res.splitlines()) == 2


def slub_object_search(cache_cmd, obj_cmd):
    cache_name = "kmalloc-256"
    chunk = get_first_slub_object_address(cache_cmd, cache_name)
    assert chunk is not None

    # Analyze some of the data in the first chunk
    res = gdb.execute(f"x/gx {chunk}", to_string=True)
    qword = res.split()[1]
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -s {qword} -S qword", to_string=True)
    assert "MATCH" in res

    res = gdb.execute(f"x/x {chunk}", to_string=True)
    dword = res.split()[1]
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -s {dword} -S dword", to_string=True)
    assert "MATCH" in res

    res = gdb.execute(f"x/hx {chunk}", to_string=True)
    halfword = res.split()[1]
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -s {halfword} -S word", to_string=True)
    assert "MATCH" in res

    res = gdb.execute(f"x/bx {chunk}", to_string=True)
    byte = res.split()[1]
    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -s {byte} -S byte", to_string=True)
    assert "MATCH" in res

    res = gdb.execute(f"{obj_cmd} -n {cache_name} {chunk} -s PWNDBG -S string", to_string=True)
    assert "NO MATCH" in res

    res = gdb.execute(
        f"{obj_cmd} -n {cache_name} {chunk} -s PWNDBG -S string --match-only", to_string=True
    )
    assert len(res.splitlines()) == 1 and "MATCH" not in res

    # depth search
    res = gdb.execute(f"x/4x {chunk}", to_string=True)
    dword1 = res.split()[1]
    dword2 = res.split()[4]
    res = gdb.execute(
        f"{obj_cmd} -n {cache_name} {chunk} -s {dword1} -S dword --depth 4", to_string=True
    )
    assert "MATCH" in res
    # We can't guarantee what's in memory atm, so just make sure it doesn't
    # match if they are different
    # TODO: We could just temporarily patch memory to make sure they're different
    if dword2 != dword1:
        res = gdb.execute(
            f"{obj_cmd} -n {cache_name} {chunk} -s {dword2} -S dword --depth 4", to_string=True
        )
        assert "NO MATCH" in res


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_object():
    """Make sure internal slub object listing is working"""

    slub_object_basic("slubcache", "slubobject")
    slub_object_highlights("slubcache", "slubobject", "slubmeta")
    slub_object_search("slubcache", "slubobject")


@pytest.mark.skipif(
    not pwndbg.gdblib.kernel.has_debug_syms() or pwndbg.gdblib.kernel.has_5lvl_paging(),
    reason="test requires debug symbols and 5-level paging",
)
def test_libslub_external_slub_object():
    """Make sure external slub object listing is working"""

    slub_object_basic("sbcache", "sbobject")
    slub_object_highlights("sbcache", "sbobject", "sbmeta")
    slub_object_search("sbcache", "sbobject")


def slub_meta(cache_cmd, meta_cmd):
    # Grab some chunk address
    res = gdb.execute(f"{cache_cmd} -n kmalloc-256 --cpu 0 --show-region", to_string=True)
    chunk = None
    for line in res.splitlines():
        if "(region start)" in line:
            chunk = line.split()[0].strip()
            break

    res = gdb.execute(f"{meta_cmd} add {chunk} tag TESTTAG", to_string=True)
    res = gdb.execute(f"{meta_cmd} list", to_string=True)
    assert "TESTTAG" in res
    assert chunk in res

    # Relist chunks, and check for metadata
    res = gdb.execute(f"{cache_cmd} -n kmalloc-256 --cpu 0 --show-region -M tag", to_string=True)
    assert "TESTTAG" in res

    res = gdb.execute(f"{meta_cmd} del {chunk}", to_string=True)
    res = gdb.execute(f"{meta_cmd} list", to_string=True)
    assert "TESTTAG" not in res

    # Relist chunks, and check for metadata
    res = gdb.execute(f"{cache_cmd} -n kmalloc-256 --cpu 0 --show-region -M tag", to_string=True)
    assert "TESTTAG" not in res

    res = gdb.execute(f"{meta_cmd} config ignore backtrace strcpy", to_string=True)
    res = gdb.execute(f"{meta_cmd} list", to_string=True)
    assert "Function ignore list for backtraces" in res
    assert "strcpy" in res

    res = gdb.execute(f"{meta_cmd} add {chunk} color green", to_string=True)
    res = gdb.execute(f"{cache_cmd} -n kmalloc-256 --cpu 0 --show-region -M color", to_string=True)
    for line in res.splitlines():
        line = line.strip()
        if f"{chunk}" in line and "(region start)" in line:
            assert line.startswith("\x1b")

    # Add a backtrace, and confirm it exists...
    res = gdb.execute(f"{meta_cmd} add {chunk} backtrace", to_string=True)
    res = gdb.execute(
        f"{cache_cmd} -n kmalloc-256 --cpu 0 --show-region -M backtrace", to_string=True
    )
    for line in res.splitlines():
        line = line.strip()
        if f"{chunk}" in line and "(region start)" in line:
            # It will look something like:
            # 0xffff8881039ec000 M | kmem_cache_free | (region start)
            assert "| (region start)" in line

    res = gdb.execute(
        f"{cache_cmd} -n kmalloc-256 --cpu 0 --show-region -M backtrace -v", to_string=True
    )
    # We expect most chunks to output this atm (which is unfortunate actually)
    assert "chunk address not found in metadata database" in res
    # Confirm that we have what seems to be a valid backtrace, we expect at least a couple functions...
    assert "#0 " in res
    assert "#1 " in res


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slub_meta():
    """Make sure external slub meta listing is working"""

    slub_meta("sbcache", "sbmeta")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_meta():
    """Make sure internal slub meta listing is working"""

    slub_meta("slubcache", "slubmeta")


def slub_db(cache_cmd, db_cmd):
    cache = "kmalloc-256"
    # Grab some chunk address
    res = gdb.execute(f"{cache_cmd} -n {cache} --cpu 0 --show-region", to_string=True)
    chunk = None
    for line in res.splitlines():
        if "(region start)" in line:
            chunk = line.split()[0].strip()
            break

    res = gdb.execute(f"{db_cmd} add kmalloc-256 {chunk}", to_string=True)
    res = gdb.execute(f"{db_cmd} list", to_string=True)
    # TODO: check for address (currently broken)
    assert cache in res

    # TODO: Add deletion (currently broken)


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_db():
    """Make sure internal slub db listing is working"""
    slub_db("slubcache", "slubdb")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slub_db():
    """Make sure external slub db listing is working"""
    slub_db("sbcache", "sbslabdb")


def slub_trace(cache_cmd, db_cmd):
    # TODO: Need a way to force adjacency for the test...
    pass


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_trace():
    """Make sure internal slub trace listing is working"""
    slub_trace("slubcache", "slubtrace")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slub_trace():
    """Make sure external slub trace listing is working"""
    slub_trace("sbcache", "sbtrace")


def slub_watch(watch_cmd):
    # TODO: We can only do this on a system we know breakpoint addrs...
    pass


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_watch():
    """Make sure internal slub watch listing is working"""
    slub_watch("slubwatch")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slub_watch():
    """Make sure external slub watch listing is working"""
    slub_watch("sbwatch")


def slub_trace(trace_cmd):
    # TODO: We can only do this on a system we know breakpoint addrs...
    pass


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_trace():
    """Make sure internal slub trace listing is working"""
    slub_trace("slubtrace")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slub_trace():
    """Make sure external slub trace listing is working"""
    slub_trace("sbtrace")


def slub_break(break_cmd):
    # TODO: We can only do this on a system we know breakpoint addrs...
    pass


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_internal_slub_break():
    """Make sure internal slub break listing is working"""
    slub_break("slubbreak")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_external_slub_break():
    """Make sure external slub break listing is working"""
    slub_break("sbbreak")


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_libslub_commands_in_help():
    """Test slub commands exist in the pwndbg help output"""
    res = gdb.execute(f"pwndbg", to_string=True)
    for name in pwndbg_internal_slub_cmd_list:
        assert name in res
