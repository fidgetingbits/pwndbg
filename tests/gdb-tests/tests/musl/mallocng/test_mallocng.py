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

    # gdb.execute("add-symbol-file tests/binaries/musls/1.2.4/lib/ld-musl-x86_64.so.1.debug")
    # gdb.execute("info sharedlibrary")
    malloc_context = pwndbg.gdblib.symbol.address("__malloc_context")
    assert malloc_context is not None

    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    assert "secret" in mheapinfo_output
