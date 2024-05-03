from __future__ import annotations

import argparse

import gdb

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.constants import mallocng
from pwndbg.heap.mallocng import MuslMallocngMemoryAllocator
from pwndbg.heap.mallocng import Printer

mheap = MuslMallocngMemoryAllocator()

# FIXME: replace with pwndbg equivalent
RED_BOLD = lambda x: "\033[1;31m" + str(x) + "\033[m"
GREEN_BOLD = lambda x: "\033[1;32m" + str(x) + "\033[m"
YLW_BOLD = lambda x: "\033[1;33m" + str(x) + "\033[m"
BLUE_BOLD = lambda x: "\033[1;34m" + str(x) + "\033[m"
MGNT_BOLD = lambda x: "\033[1;35m" + str(x) + "\033[m"
CYAN_BOLD = lambda x: "\033[1;36m" + str(x) + "\033[m"
WHT_BOLD = lambda x: "\033[1;37m" + str(x) + "\033[m"

YLW = lambda x: "\033[0;33m" + str(x) + "\033[m"
BLUE = lambda x: "\033[0;34m" + str(x) + "\033[m"
MGNT = lambda x: "\033[0;35m" + str(x) + "\033[m"
WHT = lambda x: "\033[0;37m" + str(x) + "\033[m"


def _hex(x):
    try:
        return hex(x)
    except Exception:
        # Clear sign bit with UINT64_MASK
        # XXX: Does it work in 32-bit arch?
        return hex(int(x) & pwndbg.gdblib.arch.ptrmask)


def _bin(x):
    try:
        return bin(x)
    except Exception:
        return bin(int(x) & pwndbg.gdblib.arch.ptrmask)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Dumps the musl mallocng heap state using malloc_context""",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
# @pwndbg.commands.OnlyWithResolvedHeapSyms
# @pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def mheapinfo2() -> None:
    """Display mallocng global information, like `heapinfo` command in Pwngdb

    Usage: mheapinfo"""
    if not mheap.check_mallocng():
        return

    printer = Printer(header_clr=MGNT_BOLD, content_clr=WHT_BOLD, header_rjust=16)
    P = printer.print

    # Print out useful fields in __malloc_context
    P("secret", _hex(mheap.ctx["secret"]))
    P("mmap_counter", _hex(mheap.ctx["mmap_counter"]))

    # Print out avaible meta objects
    P(
        "avail_meta",
        BLUE_BOLD(_hex(mheap.ctx["avail_meta"]))
        + WHT_BOLD(" (count: %d)" % mheap.ctx["avail_meta_count"]),
    )

    # Walk and print out free_meta chain
    m = head = mheap.ctx["free_meta_head"]
    if head:
        s = BLUE_BOLD(_hex(head))
        try:
            while head != m["next"]:
                m = m["next"]
                s += WHT_BOLD(" -> ") + BLUE_BOLD(_hex(m))
        except gdb.MemoryError:
            # Most recently accessed memory may be invaild
            s += RED_BOLD(" (Invaild memory)")
        finally:
            P("free_meta", s)
    else:
        P("free_meta", WHT_BOLD("0"))

    # Print out avaible meta areas
    P(
        "avail_meta_area",
        BLUE_BOLD(_hex(mheap.ctx["avail_meta_areas"]))
        + WHT_BOLD(" (count: %d)" % mheap.ctx["avail_meta_area_count"]),
    )

    # Walk and print out meta_area chain
    ma = mheap.ctx["meta_area_head"]
    if ma:
        s = BLUE_BOLD(_hex(ma))
        try:
            while ma["next"]:
                ma = ma["next"]
                s += WHT_BOLD(" -> ") + BLUE_BOLD(_hex(ma))
        except gdb.MemoryError:
            # Most recently accessed memory may be invaild
            s += RED_BOLD(" (Invaild memory)")
        finally:
            P("meta_area_head", s)
    else:
        P("meta_area_head", WHT_BOLD("0"))
    if mheap.ctx["meta_area_tail"]:
        P("meta_area_tail", BLUE_BOLD(_hex(mheap.ctx["meta_area_tail"])))
    else:
        P("meta_area_tail", WHT_BOLD("0"))

    # Walk active bin
    printer.set(header_clr=GREEN_BOLD, content_clr=None)
    for i in range(48):
        m = head = mheap.ctx["active"][i]
        if head:
            s = BLUE_BOLD(_hex(m))
            try:
                while True:
                    s += BLUE_BOLD(" (mem: ") + MGNT(_hex(m["mem"])) + BLUE_BOLD(")")
                    if head == m["next"]:
                        break
                    m = m["next"]
                    s += WHT_BOLD(" -> ") + BLUE_BOLD(_hex(m))
            except gdb.MemoryError:
                # Most recently accessed memory may be invaild
                s += RED_BOLD(" (Invaild memory)")
            finally:
                stride_tips = " [0x%lx]" % (mheap.size_classes[i] * mallocng.UNIT)
                P("active.[%d]" % i, s + stride_tips)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Display useful variables and functions in musl-libc
    """,
)


# FIXME: This isn't actually musl heap related, based on this: https://github.com/scwuaptx/Pwngdb
# should maybe be moved to some musl-specific command if it's kept at all
@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
@pwndbg.commands.OnlyWhenUserspace
def mmagic2() -> None:
    """Display useful variables and functions in musl-libc

    Usage: mmagic
    """
    if not mheap.check_mallocng():
        return

    libcbase = mheap.get_libcbase()
    if not libcbase:
        # Do not calculate offset if libc.so base is not availble
        get_offset = lambda x: int(x)
    else:
        get_offset = lambda x: int(x) - libcbase

    print(WHT_BOLD("====================== FUNCTIONS ======================"))
    ml = max(map(len, mallocng.MAGIC_FUNCTIONS))
    for name in mallocng.MAGIC_FUNCTIONS:
        ptr = gdb.parse_and_eval("&%s" % name)

        # Print out function offset
        info = MGNT_BOLD(name.ljust(ml)) + BLUE_BOLD(" (0x%lx)" % get_offset(ptr))
        print(info)

    print(WHT_BOLD("====================== VARIABLES ======================"))
    ml = max(map(len, mallocng.MAGIC_VARIABLES))
    for name in mallocng.MAGIC_VARIABLES:
        ptr = gdb.parse_and_eval("&%s" % name)

        value = ptr.dereference()
        t_size = value.type.sizeof
        # Generate Hex string of the variable value
        # Fill '0' to the string if its length is less than the actual size of value type
        value_hex = _hex(value).replace("0x", "")
        if t_size * 2 > len(value_hex):
            value_hex = (t_size * 2 - len(value_hex)) * "0" + value_hex

        # Print out variable info
        header = MGNT_BOLD(name.ljust(ml)) + BLUE_BOLD(" (0x%lx)" % get_offset(ptr))
        print("%s : 0x%s" % (header, value_hex))


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Find the slot index of the given address in the active bins""",
)

# FIXME: It would be nice to be able to parse expressions like: (Table *)(0x124)->array
parser.add_argument(
    "addr",
    type=int,
    nargs="?",
    default=None,
    help="Slot (aka chunk) address",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
@pwndbg.commands.OnlyWhenUserspace
def mfindslot2(addr=None) -> None:
    """Find the slot index of the given address in the active bins

    Usage: mfindslot <address>
    """
    if not mheap.check_mallocng():
        return

    if addr is None:
        print(message.error("Please provide a slot (aka chunk) address"))
        return
    gdbval = gdb.Value(addr)
    p = gdbval.cast(gdb.lookup_type("uint8_t").pointer())

    # Find slots by traversing `ctx.meta_area_head` chain
    result = mheap.search_chain(p)
    if len(result) == 0:
        print(
            message.warn(
                "Not found. This address may not be managed by mallocng or the slot meta is corrupted."
            )
        )
        return
    elif len(result) == 1:
        meta, index = result[0]
    else:
        # Multiple slots owning `p` is found.
        # It's normal because mallocng may internally use a large slot to hold group with smaller slots.
        # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n260)

        # Find slot which is actually managing `p` (the one with the smallest stride).
        meta, index = result[0]
        for x in result:
            if x[0]["sizeclass"] < meta["sizeclass"]:
                meta, index = x

    print(
        GREEN_BOLD("Found:"),
        "slot index is %s, owned by meta object at %s." % (BLUE_BOLD(index), MGNT(_hex(meta))),
    )

    # Display slot and (out-band) meta information about the slot
    try:
        mheap.display_slot(p, meta, index)
        mheap.display_meta(meta, index)
    except gdb.error as e:
        print(RED_BOLD("ERROR:"), str(e))
        return


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Display infomation of the memory allocated from mallocng

    Usage: mchunkinfo <addr>
      * addr - A memory address that can be freed by `free()`, usually the one returned from `malloc()`.
            In general, it should be a pointer to the `user_data` field of an *in-use* slot.
            (Use `mfindslot` command to explore a memory address at arbitrary offset of a slot)
    """,
)

# FIXME: It would be nice to be able to parse expressions like: (Table *)(0x124)->array

parser.add_argument(
    "addr",
    type=int,
    nargs="?",
    default=None,
    help="Slot (aka chunk) address",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
@pwndbg.commands.OnlyWhenUserspace
def mchunkinfo2(addr=None) -> None:
    """Find the slot index of the given address in the active bins

    Usage: mchunkinfo <address>
    """

    if not mheap.check_mallocng():
        return

    if addr is None:
        print(message.error("Please provide a slot (aka chunk) address"))
        return

    gdbval = gdb.Value(addr)
    p = gdbval.cast(gdb.lookup_type("uint8_t").pointer())

    # Parse in-band meta
    try:
        ib = mheap.parse_ib_meta(p)
    except gdb.error as e:
        print(RED_BOLD("ERROR:"), str(e))
        return

    # Display in-band meta information
    mheap.display_ib_meta(p, ib)

    # Get group struct object
    if not ib["overflow_in_band"]:
        offset = ib["offset16"]
    else:
        offset = ib["offset32"]
    addr = p - (offset + 1) * mallocng.UNIT
    # HACK: I had to use a custom group type because gdb can't
    # differentiate duplicate symbols :/
    group = pwndbg.gdblib.typeinfo.get_pointer_value("struct mgroup", addr)

    # Display group and (out-band) meta information
    try:
        mheap.display_group(group)
        mheap.display_meta2(ib, group)
    except gdb.error as e:
        print(RED_BOLD("ERROR:"), str(e))
        return

    # Check if we have vaild stride / sizeclass
    stride = mheap.get_stride(group["meta"])
    if stride:
        # Display the result of nontrivial_free()
        mheap.display_nontrivial_free(ib, group)

        # Compute the beginning and the ending address of slot
        slot_start = group["storage"][stride * ib["index"]].address
        slot_end = slot_start + stride - mallocng.IB

        # Display slot information
        try:
            mheap.display_slot2(p, ib, slot_start, slot_end)
        except gdb.error as e:
            print(RED_BOLD("ERROR:"), str(e))
            return
    else:
        print(
            RED_BOLD("\nCan't get slot and nontrivial_free() information due to invaild sizeclass")
        )
