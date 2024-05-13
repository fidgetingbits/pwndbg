"""
Command to print the virtual memory map a la /proc/self/maps.
"""

from __future__ import annotations

import argparse

import gdb
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.gdblib.elf
import pwndbg.gdblib.vmmap
from pwndbg.color import bold_green
from pwndbg.color import bold_red
from pwndbg.color import gray
from pwndbg.color import green
from pwndbg.color import red
from pwndbg.commands import CommandCategory
from pwndbg.gdblib import gdb_version

integer_types = (int, gdb.Value)


def pages_filter(gdbval_or_str):
    # returns a module filter
    if isinstance(gdbval_or_str, str):
        module_name = gdbval_or_str
        return lambda page: module_name in page.objfile

    # returns an address filter
    elif isinstance(gdbval_or_str, integer_types):
        addr = gdbval_or_str
        return lambda page: addr in page

    else:
        raise argparse.ArgumentTypeError("Unknown vmmap argument type.")


def print_vmmap_table_header() -> None:
    """
    Prints the table header for the vmmap command.
    """
    print(
        f"{'Start':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} {'End':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} {'Perm'} {'Size':>8} {'Offset':>6} {'File'}"
    )


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print virtual memory map pages.

Unnamed mappings are named as [anon_%#x] where %#x is high part of their start address. This is useful for filtering with `vmmap` or `search` commands.

Known issues with vmmap:
For QEMU user targets, the QEMU's gdbstub does not provide memory maps information to GDB until [0] is finished & merged. We try to deal with it without parsing the QEMU process' /proc/$pid/maps file, but if our approach fails, we simply create a [0, 0xffff...] vmmap which is not great and may result in lack of proper colors or inability to search memory with the `search` command.

For QEMU kernel, we use gdb-pt-dump that parses page tables from the guest by reading /proc/$pid/mem of QEMU process. If this does not work for you, use `set kernel-vmmap-via-page-tables off` to refer to our old method of reading vmmap info from `monitor info mem` command exposed by QEMU. Note that the latter may be slower and will not give full vmmaps permission information.

For coredump debugging, GDB also lacks all vmmap info but we do our best to get it back by using the `info proc mappings` and `maintenance info sections` commands.

As a last resort, we sometimes try to explore the addresses in CPU registers and if they are readable by GDB, we determine their bounds and create an "<explored>" vmmap. However, this method is slow and is not used on each GDB stop.

Memory pages can also be added manually with the use of vmmap_add, vmmap_clear and vmmap_load commands. This may be useful for bare metal debugging.

[0] https://lore.kernel.org/all/20220221030910.3203063-1-dominik.b.czarnota@gmail.com/""",
)
parser.add_argument(
    "gdbval_or_str",
    type=pwndbg.commands.sloppy_gdb_parse,
    nargs="?",
    default=None,
    help="Address or module name filter",
)
parser.add_argument("-w", "--writable", action="store_true", help="Display writable maps only")
parser.add_argument("-x", "--executable", action="store_true", help="Display executable maps only")
parser.add_argument(
    "-A", "--lines-after", type=int, help="Number of pages to display after result", default=1
)
parser.add_argument(
    "-B", "--lines-before", type=int, help="Number of pages to display before result", default=1
)
parser.add_argument(
    "--gaps",
    action="store_true",
    help="Display full gap information in the memory map.",
)


def print_vmmap_gaps_table_header() -> None:
    """
    Prints the table header for the vmmap command.
    """
    # FIXME: Probably the Type can change...
    # FIXME: Decide if index is useful (but I like being able to refer to multiple maps by index
    print(
        f"{'Index':>4}{'Start':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} {'End':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} {'Perm':>5} {'Size':>8} {'Type':>9} {'Accumulated Size':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}}"
    )


def print_map_gaps_only(maps):
    last_map = None
    for m in maps:
        if not last_map:
            last_map = m
            print(m)
            continue

        if m.start - last_map.end > 0x100000000:
            # We don't care if the gap is huge, like this:
            # 0x555555833000 - 0x555555a66000   0x233000 rw-p
            # 0x7fffe24f0000 - 0x7fffe3401000   0xf11000 rw-p
            print(m)
            last_map = m
            continue

        if last_map.end != m.start:
            print(m, end="")
            print(bold_red(f"GAP: {hex(m.start - last_map.end)}"))
        else:
            print(m)
        last_map = m


def calculate_total_memory(maps):
    total = 0
    for m in maps:
        total += m.size
    print(f"Total memory used: {total:#x} ({int(total/1024/1024)} MB)")


def gap_text(page):
    # Strip out offset and objfile from stringified page
    display_text = " ".join(str(page).split(" ")[:-2])
    return display_text


def print_map(page, index=None):
    if page.is_guard:
        if index is not None:
            print(gray(f"{index:4d}: "), end="")
        print(gray(f"{gap_text(page)} GUARD "))
    else:
        if index is not None:
            print(bold_green(f"{index:4d}: "), end="")
        print(bold_green(gap_text(page)))


def vmmap_gaps(pages) -> None:
    """
    Prints the gaps in the memory map.
    """
    # FIXME: A lot from this legend wont' show, so make a new one probably?
    print(f"LEGEND: {green('MAPPED')} | {gray('GUARD')} | {red('GAP')}")
    print_vmmap_gaps_table_header()

    index = -1
    last_map = None
    last_start = None
    for page in pages:
        if index is not None:
            index = index + 1
        # If this is the first map, just print it
        if not last_map:
            last_map = page
            last_start = page
            print_map(page, index)
            continue

        # If this a gap warn about it, but also print the last adjacent map set length
        if last_map.end != page.start:
            if last_start and last_start != last_map:
                if index:
                    print(bold_green(f"{index:4d}: "), end="")
                print(
                    bold_green(
                        f"{gap_text(last_map)} ADJACENT {(last_map.end - last_start.start):#x}"
                    )
                )
            # if index:
            #    print(bold_red(f"{' ':>4}"), end="")
            print(bold_red("-  " * int(57 / 3) + f" GAP {hex(page.start - last_map.end)}"))
            print_map(page, index + 1)
            last_start = page
            last_map = page
            continue
        # If this is a guard page, print the last map and the guard page
        elif page.is_guard:
            if last_start and last_start != last_map:
                if index:
                    print(bold_green(f"{index:4d}: "), end="")
                print(
                    bold_green(
                        f"{gap_text(last_map)} ADJACENT {(last_map.end - last_start.start):#x}"
                    )
                )
            print_map(page, index + 1)
            last_start = None
            last_map = page
            continue

        # If we are tracking an adjacent set, don't print the current one yet
        if last_start:
            if last_start != last_map:
                print_map(last_map, index)
        else:
            last_start = page
            print_map(page, index)
        last_map = page


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["lm", "address", "vprot", "libs"], category=CommandCategory.MEMORY
)
@pwndbg.commands.OnlyWhenRunning
def vmmap(
    gdbval_or_str=None, writable=False, executable=False, lines_after=1, lines_before=1, gaps=False
) -> None:
    lookaround_lines_limit = 64

    # Implement a sane limit
    lines_after = min(lookaround_lines_limit, lines_after)
    lines_before = min(lookaround_lines_limit, lines_before)

    # All displayed pages, including lines after and lines before
    total_pages = pwndbg.gdblib.vmmap.get()

    # Filtered memory pages, indicated by a backtrace arrow in results
    filtered_pages = []

    # Only filter when -A and -B arguments are valid
    if gdbval_or_str and lines_after >= 0 and lines_before >= 0:
        # Find matching page in memory
        filtered_pages = list(filter(pages_filter(gdbval_or_str), total_pages))
        pages_to_display = []

        for matched_page in filtered_pages:
            # Append matched page
            matched_index = total_pages.index(matched_page)

            # Include number of pages preceeding the matched page
            for before_index in range(0, lines_before + 1):
                # Guard index, and only insert the page if it is not displayed yet
                if (
                    matched_index - before_index >= 0
                    and total_pages[matched_index - before_index] not in pages_to_display
                ):
                    pages_to_display.append(total_pages[matched_index - before_index])

            # Include number of pages proceeding the matched page
            for after_index in range(1, lines_after + 1):
                if (
                    matched_index + after_index < len(total_pages) - 1
                    and total_pages[matched_index + after_index] not in pages_to_display
                ):
                    pages_to_display.append(total_pages[matched_index + after_index])

        # Sort results by address
        total_pages = sorted(pages_to_display, key=lambda page: page.vaddr)

    if not total_pages:
        print("There are no mappings for specified address or module.")
        return

    if gaps:
        vmmap_gaps(total_pages)
        return

    print(M.legend())
    print_vmmap_table_header()

    for page in total_pages:
        if (executable and not page.execute) or (writable and not page.write):
            continue

        backtrace_prefix = None
        display_text = str(page)

        if page in filtered_pages:
            # If page was one of the original results, add an arrow for clarity
            backtrace_prefix = str(pwndbg.gdblib.config.backtrace_prefix)

            # If the page is the only filtered page, insert offset
            if len(filtered_pages) == 1 and isinstance(gdbval_or_str, integer_types):
                display_text = str(page) + " +0x%x" % (int(gdbval_or_str) - page.vaddr)

        print(M.get(page.vaddr, text=display_text, prefix=backtrace_prefix))

    if pwndbg.gdblib.qemu.is_qemu() and not pwndbg.gdblib.qemu.exec_file_supported():
        print("\n[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]")

    # Only GDB versions >=12 report permission info in info proc mappings. On older versions, we fallback on "rwx".
    # See https://github.com/bminor/binutils-gdb/commit/29ef4c0699e1b46d41ade00ae07a54f979ea21cc
    if pwndbg.gdblib.qemu.is_qemu_usermode() and gdb_version[0] < 12:
        print(
            "\n[GDB <12.1 detected - vmmap cannot fetch permission information, defaulting to rwx]"
        )


parser = argparse.ArgumentParser(description="Add virtual memory map page.")
parser.add_argument("start", help="Starting virtual address")
parser.add_argument("size", help="Size of the address space, in bytes")
parser.add_argument(
    "flags", nargs="?", type=str, default="", help="Flags set by the ELF file, see PF_X, PF_R, PF_W"
)
parser.add_argument(
    "offset",
    nargs="?",
    default=0,
    help="Offset into the original ELF file that the data is loaded from",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def vmmap_add(start, size, flags, offset) -> None:
    page_flags = {
        "r": pwndbg.gdblib.elf.PF_R,
        "w": pwndbg.gdblib.elf.PF_W,
        "x": pwndbg.gdblib.elf.PF_X,
    }
    perm = 0
    for flag in flags:
        flag_val = page_flags.get(flag, None)
        if flag_val is None:
            print('Invalid page flag "%s"', flag)
            return
        perm |= flag_val

    page = pwndbg.lib.memory.Page(start, size, perm, offset)
    pwndbg.gdblib.vmmap.add_custom_page(page)

    print("%r added" % page)


@pwndbg.commands.ArgparsedCommand(
    "Clear the vmmap cache.", category=CommandCategory.MEMORY
)  # TODO is this accurate?
@pwndbg.commands.OnlyWhenRunning
def vmmap_clear() -> None:
    pwndbg.gdblib.vmmap.clear_custom_page()


parser = argparse.ArgumentParser(description="Load virtual memory map pages from ELF file.")
parser.add_argument(
    "filename", nargs="?", type=str, help="ELF filename, by default uses current loaded filename."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def vmmap_load(filename) -> None:
    if filename is None:
        filename = pwndbg.gdblib.file.get_proc_exe_file()

    print(f'Load "{filename}" ...')

    # TODO: Add an argument to let use to choose loading the page information from sections or segments

    # Use section information to recover the segment information.
    # The entry point of bare metal environment is often at the first segment.
    # For example, assume the entry point is at 0x8000.
    # In most of case, link will create a segment and starts from 0x0.
    # This cause all values less than 0x8000 be considered as a valid pointer.
    pages = []
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        for section in elffile.iter_sections():
            vaddr = section["sh_addr"]
            memsz = section["sh_size"]
            sh_flags = section["sh_flags"]
            offset = section["sh_offset"]

            # Don't add the sections that aren't mapped into memory
            if not sh_flags & SH_FLAGS.SHF_ALLOC:
                continue

            # Guess the segment flags from section flags
            flags = pwndbg.gdblib.elf.PF_R
            if sh_flags & SH_FLAGS.SHF_WRITE:
                flags |= pwndbg.gdblib.elf.PF_W
            if sh_flags & SH_FLAGS.SHF_EXECINSTR:
                flags |= pwndbg.gdblib.elf.PF_X

            page = pwndbg.lib.memory.Page(vaddr, memsz, flags, offset, filename)
            pages.append(page)

    for page in pages:
        pwndbg.gdblib.vmmap.add_custom_page(page)
        print("%r added" % page)
