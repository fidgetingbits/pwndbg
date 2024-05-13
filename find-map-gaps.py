#!/usr/bin/env python
from __future__ import annotations

import re
from dataclasses import dataclass

import gdb

# Coloring functions
RED_BOLD = lambda x: "\033[1;31m" + str(x) + "\033[m"
GREEN_BOLD = lambda x: "\033[1;32m" + str(x) + "\033[m"
YELLOW_BOLD = lambda x: "\033[1;33m" + str(x) + "\033[m"
BLUE_BOLD = lambda x: "\033[1;34m" + str(x) + "\033[m"
MGNT_BOLD = lambda x: "\033[1;35m" + str(x) + "\033[m"
CYAN_BOLD = lambda x: "\033[1;36m" + str(x) + "\033[m"
WHITE_BOLD = lambda x: "\033[1;37m" + str(x) + "\033[m"

YELLOW = lambda x: "\033[0;33m" + str(x) + "\033[m"
BLUE = lambda x: "\033[0;34m" + str(x) + "\033[m"
MGNT = lambda x: "\033[0;35m" + str(x) + "\033[m"
WHITE = lambda x: "\033[0;37m" + str(x) + "\033[m"


@dataclass
class MemoryMap:
    start: int
    end: int
    size: int
    offset: int
    perms: str

    def __str__(self):
        return f"{self.start:#014x} - {self.end:#014x} {self.size:#10x} {self.perms}"

    def __repr__(self):
        return self.__str__()


def parse_vmmap():
    """Parse memory mappings of currently running process.

    It returns a list of tuples like `(start, end, size, offset, perms)`.
    """

    result = []
    lines = gdb.execute("info proc mappings", False, True).split("\n")
    if not lines or len(lines) < 4:
        print(RED_BOLD("Warning: can't get memory mappings!\n"))
    else:
        for line in lines[4:]:
            mapping = re.findall(r"(0x\S+)\s+(0x\S+)\s+(0x\S+)\s+(0x\S+)\s+(.*)", line)
            if mapping and mapping[0]:
                start, end, size, offset, perms = mapping[0]
                # Convert to integer type
                start, end, size, offset = map(lambda x: int(x, 16), [start, end, size, offset])
                perms = perms.strip()
                # Entries with backing maps, like libraries, have the name of the mapping followed by perms
                # eg: ('0x7ffff7f78000', '0x7ffff7fc4000', '0x4c000', '0x14000', 'r-xp   /lib/ld-musl-x86_64.so.1')
                if len(perms) != 4:
                    perms = perms[:4]
                result.append(MemoryMap(start, end, size, offset, perms))
    return result


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
            print(RED_BOLD(f"  ^-- GAP: {hex(m.start - last_map.end)}"))
        else:
            print(m)
        last_map = m


def calculate_total_memory(maps):
    total = 0
    for m in maps:
        total += m.size
    print(f"Total memory used: {total:#x} ({int(total/1024/1024)} MB)")


def print_map(map, index=None):
    if map.perms == "---p":
        if index is not None:
            print(BLUE_BOLD(f"{index:4d}: "), end="")
        print(BLUE_BOLD(f"{map} !!! GUARD PAGE "))
    else:
        if index is not None:
            print(GREEN_BOLD(f"{index:4d}: "), end="")
        print(GREEN_BOLD(map))


def print_map_gaps(maps):
    index = -1  # make None too disable
    # We want to mark all maps that have gaps and any that have guard pages
    last_map = None
    last_start = None
    for m in maps:
        if index is not None:
            index = index + 1
        # If this is the first map, just print it
        if not last_map:
            last_map = m
            last_start = m
            print_map(m, index)
            continue

        # If this a gap warn about it, but also print the last adjacent map set length
        if last_map.end != m.start:
            if last_start != last_map:
                if index:
                    print(GREEN_BOLD(f"{index:4d}: "), end="")
                print(GREEN_BOLD(f"{last_map} ^-- ADJ: {(last_map.end - last_start.start):#x}"))
            if index:
                print(RED_BOLD("      "), end="")
            print(RED_BOLD("[" + "0" * 46 + f" ]-- GAP: {hex(m.start - last_map.end)}"))
            print_map(m, index + 1)
            last_start = m
            last_map = m
            continue
        # If this is a guard page, print the last map and the guard page
        elif m.perms == "---p":
            if last_start != last_map:
                if index:
                    print(GREEN_BOLD(f"{index:4d}: "), end="")
                print(GREEN_BOLD(f"{last_map} ^-- ADJ: {(last_map.end - last_start.start):#x}"))
            print_map(m, index + 1)
            last_start = None
            last_map = m
            continue

        # If we are tracking an adjacent set, don't print the current one yet
        if last_start:
            if last_start != last_map:
                print_map(last_map, index)
        else:
            last_start = m
            print_map(m, index)
        last_map = m


maps = parse_vmmap()
print_map_gaps(maps)
calculate_total_memory(maps)
