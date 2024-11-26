from __future__ import annotations

import argparse
from pwnlib.term import text

import pwndbg.color
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.constants import mallocng
from pwndbg.aglib.heap.mallocng import MuslMallocngMemoryAllocator
from pwndbg.aglib.heap.mallocng import Printer
from pwndbg.lib.common import hex

mheap = MuslMallocngMemoryAllocator()

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Dumps the musl mallocng heap state using malloc_context""",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
# @pwndbg.commands.OnlyWithResolvedHeapSyms
# @pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def mheapinfo() -> None:
    """Dumps the musl mallocng heap state using malloc_context"""
    if not mheap.check_mallocng():
        return
    printer = Printer(header_clr=text.bold_magenta, content_clr=text.bold_white, header_rjust=16)
    P = printer.print

    # Print out useful fields in __malloc_context
    P("secret", hex(mheap.ctx["secret"]))
    P("mmap_counter", hex(mheap.ctx["mmap_counter"]))

    # Print out available meta objects
    P(
        "avail_meta",
        text.bold_green(hex(mheap.ctx["avail_meta"]))
        + text.bold_white(" (count: %d)" % mheap.ctx["avail_meta_count"]),
    )

    # Walk and print out free_meta chain
    m = head = mheap.ctx["free_meta_head"]
    if head:
        s = text.bold_blue(hex(head))
        try:
            while head != m["next"]:
                m = m["next"]
                s += text.bold_white(" -> ") + text.bold_blue(hex(m))
        except pwndbg.dbg_mod.Error:
            # Most recently accessed memory may be invaild
            s += text.bold_red(" (Invaild memory)")
        finally:
            P("free_meta", s)
    else:
        P("free_meta", text.bold_white("0"))

    # Print out available meta areas
    P(
        "avail_meta_area",
        text.bold_blue(hex(mheap.ctx["avail_meta_areas"]))
        + text.bold_white(" (count: %d)" % mheap.ctx["avail_meta_area_count"]),
    )

    # Walk and print out meta_area chain
    ma = mheap.ctx["meta_area_head"]
    if ma:
        s = text.bold_blue(hex(ma))
        try:
            while ma["next"]:
                ma = ma["next"]
                s += text.bold_white(" -> ") + text.bold_blue(hex(ma))
        except pwndbg.dbg_mod.Error:
            # Most recently accessed memory may be invaild
            s += text.bold_red(" (Invalid memory)")
        finally:
            P("meta_area_head", s)
    else:
        P("meta_area_head", text.bold_white("0"))
    if mheap.ctx["meta_area_tail"]:
        P("meta_area_tail", text.bold_blue(hex(mheap.ctx["meta_area_tail"])))
    else:
        P("meta_area_tail", text.bold_white("0"))

    # Walk active bin
    printer.set(header_clr=text.bold_green, content_clr=None)
    for i in range(48):
        m = head = mheap.ctx["active"][i]
        if head:
            s = text.bold_blue(hex(m))
            try:
                while True:
                    s += (
                        text.bold_blue(" (mem: ")
                        + text.magenta(hex(m["mem"]))
                        + text.bold_blue(")")
                    )
                    if hex(head) == hex(m["next"]):
                        break
                    m = m["next"]
                    s += text.bold_white(" -> ") + text.bold_blue(hex(m))
            except pwndbg.dbg_mod.Error:
                # Most recently accessed memory may be invaild
                s += text.bold_red(" (Invaild memory)")
            finally:
                stride_tips = " [0x%lx]" % (mheap.size_classes[i] * mallocng.UNIT)
                P("active.[%d]" % i, s + stride_tips)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Display useful variables and functions in musl-libc
    """,
)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Find the musl mallocng slot index of the given address

    Usage: mfindslot <address>
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
def mfindslot(addr: int | None = None) -> None:
    """Find the musl mallocng slot index of the given address

    This works by traversing the `ctx.meta_area_head` chain of meta structures and checking if the given address
    is within the associated group.
    """
    if not mheap.check_mallocng():
        return

    if addr is None:
        print(message.error("Please provide a slot (aka chunk) address"))
        return

    # Find slots by traversing `ctx.meta_area_head` chain
    result = mheap.search_chain(addr)
    if len(result) == 0:
        print(
            message.warn(
                "Not found. Address may not be managed by mallocng or the slot meta is corrupted."
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
            if int(x[0]["sizeclass"]) < int(meta["sizeclass"]):
                meta, index = x

    print(
        text.bold_green("Found:"),
        "slot index is %s, owned by meta object at %s."
        % (text.bold_blue(str(index)), text.magenta(hex(meta))),
    )

    # Display slot and (out-of-band) meta information about the slot
    try:
        mheap.display_meta(meta, index=index)
        if meta == 0:
            return
        mheap.display_ob_slot(addr, meta, index)
    except pwndbg.dbg_mod.Error as e:
        print(message.error("ERROR: " + str(e)))
        return


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Display the musl mallocng slot (aka chunk) details

    Usage: mslotinfo <addr>
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
def mslotinfo(addr: int | None = None) -> None:
    """Display the musl mallocng slot (aka chunk) details"""

    if not mheap.check_mallocng():
        return

    if addr is None:
        print(message.error("Please provide a slot (aka chunk) address"))
        return

    p = pwndbg.dbg.selected_inferior().create_value(addr, pwndbg.aglib.typeinfo.pchar)
    # type = pwndbg.aglib.typeinfo.lookup_types("uint8_t")
    # p = val.cast(type.pointer())
    # p = addr

    # Parse in-band meta
    try:
        ib = mheap.parse_ib_meta(int(p))
    except pwndbg.dbg_mod.Error as e:
        print(message.error("ERROR:"), str(e))
        return

    # Display in-band meta information
    mheap.display_ib_meta(int(p), ib)

    # Get group struct object
    if not int(ib["overflow_in_band"]):
        offset = int(ib["offset16"])
    else:
        offset = int(ib["offset32"])
    addr = p - (offset + 1) * mallocng.UNIT
    group_type = mheap.get_group_type()
    if not group_type:
        print(message.error("Failed to get mallocng group type"))
        return
    group = pwndbg.aglib.memory.get_typed_pointer_value(group_type, addr)
    if not group:
        print(message.error("ERROR:"), "Failed to get group object")
        return

    # Display group and (out-band) meta information
    try:
        mheap.display_group(group)
        meta = group["meta"]
        if not int(meta):
            print(message.error("Failed to find meta object"))
            return
        mheap.display_meta(meta, ib=ib)
    except pwndbg.dbg_mod.Error as e:
        print(message.error("ERROR:"), str(e))
        return

    # Check if we have vaild stride / sizeclass
    stride = mheap.get_stride(group["meta"])
    if stride:
        # Display the result of nontrivial_free()
        mheap.display_nontrivial_free(ib, group)

        # Display slot information
        try:
            mheap.display_ib_slot(p, group["meta"], ib)
        except pwndbg.dbg_mod.Error as e:
            print(message.error("ERROR:"), str(e))
            return
    else:
        print(
            message.error(
                "\nCan't get slot and nontrivial_free() information due to invaild sizeclass"
            )
        )
