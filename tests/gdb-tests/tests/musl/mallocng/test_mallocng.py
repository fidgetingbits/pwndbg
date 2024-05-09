from __future__ import annotations

import os
import tempfile

import gdb
import pytest

import pwndbg
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
    start_binary(HEAP_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Make sure at least one command works
    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    assert "secret" in mheapinfo_output


def test_musl_mallocng_mslotfind(start_binary):
    pass


def test_musl_mallocng_mslotinfo(start_binary):
    # Use mheapinfo to grab an active group. The group itself should be a slot
    # Use mfindslot to get the real slot
    # Use mslotinfo to get the slot info to test
    # NOTE: Once we abstract the structures to automatically pull out values without relying on the commands, this
    # will change
    pass
