from __future__ import annotations

import os
import tempfile

import gdb
import pytest

import pwndbg
import pwndbg.lib.strings
import tests

HEAP_BINARY = tests.binaries.get("musl_mallocng_initialized.out")


def test_musl_mallocng_mheap(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    print(gdb.execute("!pwd"))
    # gdb.execute("add-symbol-file tests/binaries/musls/1.2.4/lib/ld-musl-x86_64.so.1.debug")
    # gdb.execute("info sharedlibrary")
    malloc_context = pwndbg.gdblib.symbol.address("__malloc_context")
    assert malloc_context is not None

    # Make sure at least one command works
    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    assert "secret" in mheapinfo_output


def test_musl_mallocng_mheapinfo(start_binary):
    """Make sure all expected fields are output"""

    start_binary(HEAP_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Make sure at least one command works
    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    mheapinfo_output = pwndbg.lib.strings.strip_colors(mheapinfo_output)
    assert "secret" in mheapinfo_output
    assert "mmap_counter" in mheapinfo_output
    assert "avail_meta" in mheapinfo_output
    assert "free_meta" in mheapinfo_output
    assert "avail_meta_area" in mheapinfo_output
    assert "meta_area_head" in mheapinfo_output
    assert "meta_area_tail" in mheapinfo_output

    assert "active.[0]" in mheapinfo_output
    for line in mheapinfo_output.splitlines():
        if "active.[0]" in line:
            assert line.endswith("[0x10]")


def test_musl_mallocng_mslotfind(start_binary):
    pass


def test_musl_mallocng_mslotinfo(start_binary):
    # Use mheapinfo to grab an active group. The group itself should be a slot
    # Use mfindslot to get the real slot
    # Use mslotinfo to get the slot info to test
    # NOTE: Once we abstract the structures to automatically pull out values without relying on the commands, this
    # will change
    pass
